use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::num::{NonZeroU16, NonZeroU8};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr as _;
use std::time::Duration;

use bitcoin::Network;
use sha2::{Digest, Sha256};
use tendermint::node::Id as CometNodeId;
use thunderbolt_bitcoin::RpcConfig;
use thunderbolt_cometbft::{FinalityPolicy, THUNDERBOLT_APP_VERSION_V2};
use thunderbolt_cometbft_client::{
    CoordinatorConfig, CoordinatorLimits, HistoryEpochLimits, PeerIdentity, SourceConfiguration,
    TrustCoordinatorIdentity,
};
use thunderbolt_cometbft_rpc::{RetryPolicy as CometRpcRetryPolicy, RpcLimits};
use thunderbolt_committee::CommitteeMemberId;
use thunderbolt_committee_node::{
    FinalityCoordinatorId as CommitteeFinalityCoordinatorId,
    FinalityVerifierProfileId as CommitteeFinalityVerifierProfileId, NodeConfig as CommitteeNodeConfig,
};
use thunderbolt_control::{ControlServerConfig, ABSOLUTE_MAX_FRAME_BYTES};
use thunderbolt_holder_node::{
    FinalityCoordinatorId as HolderFinalityCoordinatorId, FinalityVerifierProfileId as HolderFinalityVerifierProfileId,
    HolderDeploymentPolicy, HolderNodeConfig, RetryPolicy,
};
use thunderbolt_ledger::LedgerChainIdV2;
use thunderbolt_ledger_abci::{
    ConsensusProfileV2, ProcessExitFatalHandler, StaticAdmissionRequestV2, StaticAdmissionVerifierV2,
    MAX_BLOCK_TRANSACTION_BYTES, MAX_PREPARE_SCAN_BYTES, MAX_PREPARE_SCAN_TRANSACTIONS, MAX_TRANSACTION_BYTES,
};
use thunderbolt_ledger_app::{ApplicationOptions, APPLICATION_VERSION_V2};
use thunderbolt_protocol::v2::ProtocolLimitsV2;
use thunderbolt_wire::{
    AnchorParameterSuiteIdV2, BitcoinGenesisHashV2, ChannelBindingV2, CommitteeDescriptorDigestV2, DeploymentId,
    FundingOutpointV2, ProtocolSuiteIdV2,
};
use toml::Value;
use url::{Host, Url};

use crate::raw::{
    RawAbci, RawApplication, RawBitcoin, RawCapabilities, RawCheckpointProviderReference, RawComet, RawCometPeer,
    RawCometTlsReferences, RawCommitteeProcess, RawControl, RawDeploymentMode, RawDocument, RawHolderProcess,
    RawIdentity, RawLedgerPaths, RawLedgerProcess, RawNetwork, RawPaillierProfile, RawProcess, RawPublicFileReference,
    RawRolePaths, RawSecretFileReference, RawSigningMode,
};
use crate::types::{
    AbciRuntimePolicy, CandidateConfig, CapabilityBoundary, CometPeerPolicy, CometRuntimePolicy, CometTlsReferences,
    CommitteeRuntimeConfig, DeploymentIdentity, ExternalCheckpointProviderRequirement, ExternalFileReference,
    HolderRuntimeConfig, LedgerRuntimeConfig, ParsedCometPeer, ParsedRuntimeConfig, RuntimePaths, SecretFileReference,
    TrustRootReference, CONFIG_VERSION_V2,
};
use crate::{ConfigError, Result};

const MAX_CONFIG_BYTES: usize = 256 * 1_024;
const MAX_ABCI_FRAME_BYTES: usize = 26 * 1_024 * 1_024;
const MAX_MEMPOOL_TRANSACTIONS: usize = MAX_PREPARE_SCAN_TRANSACTIONS;
const MAX_MEMPOOL_BYTES: usize = MAX_PREPARE_SCAN_BYTES;
const MAX_ADMISSION_REQUESTS_PER_SECOND: u32 = 10_000;
const MAX_ABCI_CONNECTIONS: u16 = 128;
const MAX_SUPERVISOR_RESTARTS: u16 = 100;
const MAX_SUPERVISOR_WINDOW_SECONDS: u64 = 3_600;
const MIN_SUPERVISOR_BACKOFF_MS: u64 = 10;
const MAX_SUPERVISOR_BACKOFF_MS: u64 = 60_000;

impl ParsedRuntimeConfig {
    /// Parses a bounded version-two TOML document and maps every field through
    /// the committed policy constructors. Filesystem references remain
    /// unaudited until [`Self::validate_filesystem`] is called.
    pub fn parse_toml(input: &str) -> Result<Self> {
        if input.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::InputTooLarge);
        }
        let value: Value = toml::from_str(input).map_err(|_| ConfigError::InvalidToml)?;
        reject_secret_keys(&value)?;
        let raw: RawDocument = toml::from_str(input).map_err(|_| ConfigError::InvalidToml)?;
        if raw.config_version != CONFIG_VERSION_V2 {
            return Err(ConfigError::UnsupportedVersion);
        }
        let candidate = match raw.process {
            RawProcess::Ledger(value) => CandidateConfig::Ledger(map_ledger(value)?),
            RawProcess::Holder(value) => CandidateConfig::Holder(map_holder(value)?),
            RawProcess::Committee(value) => CandidateConfig::Committee(map_committee(value)?),
        };
        validate_distinct_writable_paths(candidate.paths())?;
        Ok(Self { candidate })
    }
}

fn map_ledger(raw: RawLedgerProcess) -> Result<LedgerRuntimeConfig> {
    let paths = map_ledger_paths(raw.paths)?;
    let identity = map_identity(&raw.identity, &paths)?;
    validate_capabilities(&raw.capabilities)?;
    let protocol_limits = map_protocol_limits(&raw.application)?;
    let static_verifier_profile_id = derive_id(
        b"bitcoin-thunderbolt/runtime-config/static-verifier-profile/v2",
        &identity.profile_manifest_digest,
    );
    let deployment_descriptor_digest = deployment_descriptor_digest(&identity);
    require_hex32(
        &raw.ledger_profiles.static_verifier_profile_id,
        true,
        "static verifier profile",
    )?
    .eq(&static_verifier_profile_id)
    .then_some(())
    .ok_or(ConfigError::Invalid(
        "static verifier profile is not derived from profile manifest",
    ))?;
    require_hex32(
        &raw.ledger_profiles.deployment_descriptor_digest,
        true,
        "deployment descriptor",
    )?
    .eq(&deployment_descriptor_digest)
    .then_some(())
    .ok_or(ConfigError::Invalid(
        "deployment descriptor digest is not derived from canonical identity",
    ))?;
    let profile_identity = ConfiguredVerifierIdentity {
        verifier_profile_id: static_verifier_profile_id,
        deployment_descriptor: deployment_descriptor_digest,
    };
    let consensus_profile =
        ConsensusProfileV2::from_verifier(&identity.ledger_chain_id, protocol_limits, &profile_identity)
            .map_err(|_| ConfigError::PolicyRejected)?;
    let expected_consensus = require_hex32(&raw.ledger_profiles.consensus_profile_digest, true, "consensus profile")?;
    if consensus_profile.as_bytes() != &expected_consensus {
        return Err(ConfigError::Invalid(
            "consensus profile digest does not match committed derivation",
        ));
    }
    let application_options = ApplicationOptions {
        busy_timeout: duration_ms(raw.application.busy_timeout_ms)?,
        protocol_limits,
        consensus_profile_digest: Some(*consensus_profile.as_bytes()),
    };
    if application_options.busy_timeout.is_zero() || application_options.busy_timeout > Duration::from_secs(60) {
        return Err(ConfigError::PolicyRejected);
    }
    let abci = map_abci(raw.abci)?;
    let bitcoin = map_bitcoin(raw.bitcoin, identity.network)?;
    let control = map_control(raw.control, &paths.control_socket)?;
    Ok(LedgerRuntimeConfig {
        identity,
        paths,
        application_options,
        consensus_profile,
        static_verifier_profile_id,
        deployment_descriptor_digest,
        abci,
        bitcoin,
        control,
        capabilities: CapabilityBoundary,
        filesystem_audit: None,
    })
}

fn map_holder(raw: RawHolderProcess) -> Result<HolderRuntimeConfig> {
    let paths = map_role_paths(raw.paths)?;
    let identity = map_identity(&raw.identity, &paths)?;
    if comet_policy_digest(&raw.comet, &identity, &paths)? != identity.finality_policy_digest {
        return Err(ConfigError::Invalid(
            "Comet policy does not match the finality profile commitment",
        ));
    }
    validate_capabilities(&raw.capabilities)?;
    let comet = map_comet(raw.comet, &identity, &paths)?;
    let channel = channel_template(&identity)?;
    let deployment = HolderDeploymentPolicy::from_channel(&channel).map_err(|_| ConfigError::PolicyRejected)?;
    let retry = RetryPolicy {
        initial_delay_ms: raw.holder.retry_initial_delay_ms,
        maximum_delay_ms: raw.holder.retry_maximum_delay_ms,
        maximum_attempts: raw.holder.retry_maximum_attempts,
    };
    let finality_profile = HolderFinalityVerifierProfileId::new(identity.finality_verifier_profile_id)
        .map_err(|_| ConfigError::PolicyRejected)?;
    let finality_coordinator = HolderFinalityCoordinatorId::new(*comet.coordinator().identity().as_bytes())
        .map_err(|_| ConfigError::PolicyRejected)?;
    let node = HolderNodeConfig::new(
        identity.network,
        identity.ledger_chain_id.clone(),
        finality_profile,
        finality_coordinator,
        deployment,
        retry,
        raw.holder.submit_batch,
        raw.holder.finality_batch,
        duration_ms(raw.holder.busy_timeout_ms)?,
    )
    .map_err(|_| ConfigError::PolicyRejected)?;
    let bitcoin = map_bitcoin(raw.bitcoin, identity.network)?;
    let control = map_control(raw.control, &paths.control_socket)?;
    Ok(HolderRuntimeConfig {
        identity,
        paths,
        node,
        comet,
        bitcoin,
        control,
        capabilities: CapabilityBoundary,
        filesystem_audit: None,
    })
}

fn map_committee(raw: RawCommitteeProcess) -> Result<CommitteeRuntimeConfig> {
    let paths = map_role_paths(raw.paths)?;
    let identity = map_identity(&raw.identity, &paths)?;
    if comet_policy_digest(&raw.comet, &identity, &paths)? != identity.finality_policy_digest {
        return Err(ConfigError::Invalid(
            "Comet policy does not match the finality profile commitment",
        ));
    }
    validate_capabilities(&raw.capabilities)?;
    let comet = map_comet(raw.comet, &identity, &paths)?;
    CommitteeNodeConfig::validate_network(identity.network).map_err(|_| ConfigError::PolicyRejected)?;
    let member_id = CommitteeMemberId::new(raw.committee.member_id).map_err(|_| ConfigError::PolicyRejected)?;
    let finality = CommitteeFinalityVerifierProfileId::new(identity.finality_verifier_profile_id)
        .map_err(|_| ConfigError::PolicyRejected)?;
    let coordinator = CommitteeFinalityCoordinatorId::new(*comet.coordinator().identity().as_bytes())
        .map_err(|_| ConfigError::PolicyRejected)?;
    let node = CommitteeNodeConfig::new(
        identity.ledger_chain_id.clone(),
        finality,
        coordinator,
        raw.committee.max_inbox_rows,
        raw.committee.max_outbox_rows,
        raw.committee.fetch_batch_size,
    )
    .map_err(|_| ConfigError::PolicyRejected)?;
    let bitcoin = map_bitcoin(raw.bitcoin, identity.network)?;
    let control = map_control(raw.control, &paths.control_socket)?;
    Ok(CommitteeRuntimeConfig {
        identity,
        paths,
        node,
        member_id,
        comet,
        bitcoin,
        control,
        capabilities: CapabilityBoundary,
        filesystem_audit: None,
    })
}

fn map_identity(raw: &RawIdentity, paths: &RuntimePaths) -> Result<DeploymentIdentity> {
    let network = map_network(raw.network)?;
    if raw.application_version != APPLICATION_VERSION_V2 || raw.application_version != THUNDERBOLT_APP_VERSION_V2 {
        return Err(ConfigError::Invalid("application version must be exactly 2"));
    }
    if raw.committee_epoch == 0 {
        return Err(ConfigError::Invalid("committee epoch must be positive"));
    }
    let ledger_chain_id = LedgerChainIdV2::new(&raw.ledger_chain_id).map_err(|_| ConfigError::PolicyRejected)?;
    let deployment_id = decode_hex(&raw.deployment_id_hex, 1, thunderbolt_wire::MAX_DEPLOYMENT_ID_BYTES)?;
    let _ =
        DeploymentId::from_bytes("runtime.deployment_id", &deployment_id).map_err(|_| ConfigError::PolicyRejected)?;
    let protocol_suite_id =
        ProtocolSuiteIdV2::from_bytes(require_hex32(&raw.protocol_suite_id, true, "protocol suite")?)
            .map_err(|_| ConfigError::PolicyRejected)?;
    let bitcoin_genesis_hash =
        BitcoinGenesisHashV2::from_bytes(require_hex32(&raw.bitcoin_genesis_hash, false, "Bitcoin genesis hash")?)
            .map_err(|_| ConfigError::PolicyRejected)?;
    let expected_genesis = BitcoinGenesisHashV2::for_network(network).map_err(|_| ConfigError::PolicyRejected)?;
    if bitcoin_genesis_hash != expected_genesis {
        return Err(ConfigError::Invalid("Bitcoin genesis hash does not match network"));
    }
    let committee_descriptor_digest = CommitteeDescriptorDigestV2::from_bytes(require_hex32(
        &raw.committee_descriptor_digest,
        true,
        "committee descriptor",
    )?)
    .map_err(|_| ConfigError::PolicyRejected)?;
    if committee_descriptor_digest.as_bytes() != paths.committee_descriptor.digest {
        return Err(ConfigError::Invalid(
            "committee descriptor id does not match canonical descriptor reference",
        ));
    }
    let anchor_parameter_suite_id =
        AnchorParameterSuiteIdV2::from_bytes(require_hex32(&raw.anchor_parameter_suite_id, true, "anchor suite")?)
            .map_err(|_| ConfigError::PolicyRejected)?;
    if anchor_parameter_suite_id.as_bytes() != paths.anchor_suite_registry.digest {
        return Err(ConfigError::Invalid(
            "anchor suite id does not match canonical registry reference",
        ));
    }
    let runtime_profile_id = derive_id(
        b"bitcoin-thunderbolt/runtime-config/runtime-profile/v2",
        &paths.profile_manifest.digest,
    );
    let finality_policy_digest = require_hex32(&raw.finality_policy_digest, true, "finality policy digest")?;
    let finality_verifier_profile_id = derive_finality_profile_id(
        b"bitcoin-thunderbolt/runtime-config/finality-verifier-profile/v2",
        &paths.profile_manifest.digest,
        &finality_policy_digest,
    );
    if require_hex32(&raw.runtime_profile_id, true, "runtime profile")? != runtime_profile_id
        || require_hex32(&raw.finality_verifier_profile_id, true, "finality verifier profile")?
            != finality_verifier_profile_id
    {
        return Err(ConfigError::Invalid(
            "profile ids are not derived from canonical manifest",
        ));
    }
    if paths
        .vault_checkpoint_provider
        .as_ref()
        .is_some_and(|provider| provider.policy_profile_id != runtime_profile_id)
        || paths
            .trust_checkpoint_provider
            .as_ref()
            .is_some_and(|provider| provider.policy_profile_id != finality_verifier_profile_id)
    {
        return Err(ConfigError::Invalid(
            "checkpoint provider policy profile does not match canonical manifest",
        ));
    }
    Ok(DeploymentIdentity {
        network,
        ledger_chain_id,
        deployment_id,
        protocol_suite_id,
        bitcoin_genesis_hash,
        committee_epoch: raw.committee_epoch,
        committee_descriptor_digest,
        anchor_parameter_suite_id,
        runtime_profile_id,
        finality_verifier_profile_id,
        finality_policy_digest,
        profile_manifest_digest: paths.profile_manifest.digest,
    })
}

fn validate_capabilities(raw: &RawCapabilities) -> Result<()> {
    if !matches!(raw.deployment_mode, RawDeploymentMode::NonProduction)
        || !matches!(raw.holder_signing, RawSigningMode::Unavailable)
        || !matches!(raw.committee_threshold_signing, RawSigningMode::Unavailable)
        || !matches!(raw.paillier_profile, RawPaillierProfile::LegacyRc2048V1)
    {
        return Err(ConfigError::Invalid(
            "production signing and Paillier-3072 capability claims are blocked",
        ));
    }
    Ok(())
}

fn map_network(raw: RawNetwork) -> Result<Network> {
    match raw {
        RawNetwork::Regtest => Ok(Network::Regtest),
        RawNetwork::Signet => Ok(Network::Signet),
        RawNetwork::Testnet3 => Ok(Network::Testnet),
        RawNetwork::Testnet4 | RawNetwork::Mainnet => Err(ConfigError::Invalid(
            "mainnet and Testnet4 runtime configurations are disabled",
        )),
    }
}

fn map_protocol_limits(raw: &RawApplication) -> Result<ProtocolLimitsV2> {
    ProtocolLimitsV2::new(
        raw.max_entries_per_channel,
        raw.max_pending_invoices,
        raw.max_invoice_ttl_ms,
    )
    .map_err(|_| ConfigError::PolicyRejected)
}

fn map_bitcoin(raw: RawBitcoin, network: Network) -> Result<RpcConfig> {
    let endpoint = Url::parse(&raw.endpoint).map_err(|_| ConfigError::Invalid("Bitcoin endpoint URL is invalid"))?;
    RpcConfig::new(endpoint, network)
        .and_then(|config| {
            config.with_timeouts(
                duration_ms(raw.request_timeout_ms)
                    .map_err(|_| thunderbolt_bitcoin::BitcoinError::InvalidConfig("duration"))?,
                duration_ms(raw.connect_timeout_ms)
                    .map_err(|_| thunderbolt_bitcoin::BitcoinError::InvalidConfig("duration"))?,
            )
        })
        .and_then(|config| config.with_body_limits(raw.max_request_bytes, raw.max_response_bytes))
        .and_then(|config| {
            config.with_read_retry(
                raw.read_attempts,
                duration_ms(raw.retry_delay_ms)
                    .map_err(|_| thunderbolt_bitcoin::BitcoinError::InvalidConfig("duration"))?,
            )
        })
        .and_then(|config| config.with_max_chain_sync_blocks(raw.max_chain_sync_blocks))
        .map_err(|_| ConfigError::PolicyRejected)
}

fn map_control(raw: RawControl, socket_path: &Path) -> Result<ControlServerConfig> {
    let io_timeout = duration_ms(raw.io_timeout_ms)?;
    let handler_timeout = duration_ms(raw.handler_timeout_ms)?;
    let shutdown_grace = duration_ms(raw.shutdown_grace_ms)?;
    if raw.max_frame_bytes < 64
        || raw.max_frame_bytes > ABSOLUTE_MAX_FRAME_BYTES
        || raw.max_concurrent_requests == 0
        || raw.max_concurrent_requests > 1_024
        || raw.max_inflight_bytes < raw.max_frame_bytes.checked_mul(2).ok_or(ConfigError::PolicyRejected)?
        || raw.max_inflight_bytes > 256 * 1_024 * 1_024
        || io_timeout.is_zero()
        || io_timeout > Duration::from_secs(60)
        || handler_timeout.is_zero()
        || handler_timeout > Duration::from_secs(300)
        || shutdown_grace.is_zero()
        || shutdown_grace > Duration::from_secs(300)
    {
        return Err(ConfigError::PolicyRejected);
    }
    Ok(ControlServerConfig {
        socket_path: socket_path.to_path_buf(),
        max_frame_bytes: raw.max_frame_bytes,
        max_concurrent_requests: raw.max_concurrent_requests,
        max_inflight_bytes: raw.max_inflight_bytes,
        io_timeout,
        handler_timeout,
        shutdown_grace,
        recover_stale_socket: false,
    })
}

fn map_abci(raw: RawAbci) -> Result<AbciRuntimePolicy> {
    let bind_address =
        SocketAddr::from_str(&raw.bind_address).map_err(|_| ConfigError::Invalid("ABCI bind address is invalid"))?;
    if !bind_address.ip().is_loopback()
        || bind_address.port() == 0
        || !(MAX_TRANSACTION_BYTES..=MAX_ABCI_FRAME_BYTES).contains(&raw.max_frame_bytes)
        || raw.mempool_max_transactions == 0
        || raw.mempool_max_transactions > MAX_MEMPOOL_TRANSACTIONS
        || !(MAX_TRANSACTION_BYTES..=MAX_MEMPOOL_BYTES).contains(&raw.mempool_max_bytes)
        || raw.admission_requests_per_second == 0
        || raw.admission_requests_per_second > MAX_ADMISSION_REQUESTS_PER_SECOND
        || raw.max_connections == 0
        || raw.max_connections > MAX_ABCI_CONNECTIONS
        || raw.minimum_fee == 0
        || raw.supervisor_max_restarts == 0
        || raw.supervisor_max_restarts > MAX_SUPERVISOR_RESTARTS
        || raw.supervisor_window_seconds == 0
        || raw.supervisor_window_seconds > MAX_SUPERVISOR_WINDOW_SECONDS
        || !(MIN_SUPERVISOR_BACKOFF_MS..=MAX_SUPERVISOR_BACKOFF_MS).contains(&raw.supervisor_backoff_ms)
        || raw.mempool_max_bytes > MAX_BLOCK_TRANSACTION_BYTES.saturating_add(8 * 1_024 * 1_024)
    {
        return Err(ConfigError::PolicyRejected);
    }
    let _ = ProcessExitFatalHandler::new(raw.fatal_exit_code).map_err(|_| ConfigError::PolicyRejected)?;
    Ok(AbciRuntimePolicy {
        bind_address,
        max_frame_bytes: raw.max_frame_bytes,
        mempool_max_transactions: raw.mempool_max_transactions,
        mempool_max_bytes: raw.mempool_max_bytes,
        admission_requests_per_second: raw.admission_requests_per_second,
        max_connections: raw.max_connections,
        minimum_fee: raw.minimum_fee,
        fatal_exit_code: raw.fatal_exit_code,
        supervisor_max_restarts: raw.supervisor_max_restarts,
        supervisor_window_seconds: raw.supervisor_window_seconds,
        supervisor_backoff_ms: raw.supervisor_backoff_ms,
    })
}

fn map_comet(raw: RawComet, identity: &DeploymentIdentity, paths: &RuntimePaths) -> Result<CometRuntimePolicy> {
    let policy = FinalityPolicy::new(
        duration_seconds(raw.trusting_period_seconds)?,
        duration_ms(raw.clock_drift_ms)?,
        raw.max_validators,
        raw.max_adjacent_headers,
        raw.min_witnesses,
        raw.max_witnesses,
    )
    .map_err(|_| ConfigError::PolicyRejected)?;
    let primary = map_comet_peer(raw.primary, identity.network)?;
    let witnesses = raw
        .witnesses
        .into_iter()
        .map(|peer| map_comet_peer(peer, identity.network))
        .collect::<Result<Vec<_>>>()?;
    let mut endpoint_set = BTreeSet::new();
    if !endpoint_set.insert(primary.endpoint.as_str().to_owned())
        || witnesses
            .iter()
            .any(|peer| !endpoint_set.insert(peer.endpoint.as_str().to_owned()))
    {
        return Err(ConfigError::Invalid(
            "Comet primary and witness endpoints must be distinct",
        ));
    }
    let https_count = std::iter::once(&primary)
        .chain(witnesses.iter())
        .filter(|peer| peer.endpoint.scheme() == "https")
        .count();
    let peer_count = witnesses.len().checked_add(1).ok_or(ConfigError::PolicyRejected)?;
    if https_count != 0 && https_count != peer_count {
        return Err(ConfigError::Invalid(
            "Comet HTTP and HTTPS peer profiles cannot be mixed",
        ));
    }
    if (https_count == peer_count) != paths.comet_tls.is_some() {
        return Err(ConfigError::Invalid(
            "HTTPS Comet peers require pinned CA and client-identity references",
        ));
    }
    let sources = SourceConfiguration::new(
        raw.source_version,
        primary.identity.clone(),
        witnesses.iter().map(|peer| peer.identity.clone()).collect(),
    )
    .map_err(|_| ConfigError::PolicyRejected)?;
    let limits = CoordinatorLimits::new(
        raw.max_trace_encoded_bytes,
        raw.max_execution_encoded_bytes,
        raw.max_proof_bundle_bytes,
        duration_ms(raw.operation_timeout_ms)?,
        witnesses.len(),
    )
    .map_err(|_| ConfigError::PolicyRejected)?;
    let rpc_limits = RpcLimits::new(
        raw.rpc_response_bytes,
        raw.rpc_aggregate_bytes,
        raw.max_adjacent_headers,
        raw.max_validators,
        NonZeroU8::new(raw.rpc_validator_page_size).ok_or(ConfigError::PolicyRejected)?,
        raw.rpc_max_headers,
        raw.rpc_max_header_bytes,
    )
    .map_err(|_| ConfigError::PolicyRejected)?;
    if raw.rpc_aggregate_bytes > raw.max_trace_encoded_bytes {
        return Err(ConfigError::Invalid(
            "RPC aggregate bytes exceed the coordinator trace bound",
        ));
    }
    let rpc_retry = CometRpcRetryPolicy::new(
        NonZeroU8::new(raw.rpc_retry_attempts).ok_or(ConfigError::PolicyRejected)?,
        duration_ms(raw.rpc_retry_base_delay_ms)?,
    )
    .map_err(|_| ConfigError::PolicyRejected)?;
    let history_limits = HistoryEpochLimits::new(
        raw.history_max_transitions,
        raw.history_max_proof_bytes,
        raw.history_max_requests,
    )
    .map_err(|_| ConfigError::PolicyRejected)?;
    let coordinator_identity = TrustCoordinatorIdentity::new(require_hex32(
        &raw.coordinator_identity,
        true,
        "trust coordinator identity",
    )?)
    .map_err(|_| ConfigError::PolicyRejected)?;
    let coordinator = CoordinatorConfig::new(
        coordinator_identity,
        identity.ledger_chain_id.clone(),
        policy,
        sources,
        duration_ms(raw.busy_timeout_ms)?,
        limits,
        history_limits,
    )
    .map_err(|_| ConfigError::PolicyRejected)?;
    if raw.trust_root_height == 0 {
        return Err(ConfigError::Invalid("Comet trust-root height must be positive"));
    }
    let trust_root = TrustRootReference {
        height: raw.trust_root_height,
        header_hash: require_hex32(&raw.trust_root_header_hash, true, "Comet trust-root hash")?,
        light_block: paths
            .trust_root_light_block
            .clone()
            .ok_or(ConfigError::Invalid("Comet trust-root reference is missing"))?,
    };
    Ok(CometRuntimePolicy {
        coordinator,
        primary: CometPeerPolicy {
            endpoint: primary.endpoint,
            identity: primary.identity,
        },
        witnesses: witnesses
            .into_iter()
            .map(|peer| CometPeerPolicy {
                endpoint: peer.endpoint,
                identity: peer.identity,
            })
            .collect(),
        trust_root,
        rpc_limits,
        rpc_retry,
    })
}

fn map_comet_peer(raw: RawCometPeer, network: Network) -> Result<ParsedCometPeer> {
    if raw.node_id.len() != 40
        || !raw
            .node_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ConfigError::Invalid(
            "Comet node id must be 40 lowercase hexadecimal characters",
        ));
    }
    let node_id = CometNodeId::from_str(&raw.node_id).map_err(|_| ConfigError::PolicyRejected)?;
    let transport_binding = require_hex32(&raw.transport_binding_sha256, true, "Comet transport binding")?;
    let identity = PeerIdentity::new(transport_binding, node_id).map_err(|_| ConfigError::PolicyRejected)?;
    let endpoint = Url::parse(&raw.endpoint).map_err(|_| ConfigError::Invalid("Comet endpoint URL is invalid"))?;
    validate_authenticated_endpoint(&endpoint, network)?;
    Ok(ParsedCometPeer { endpoint, identity })
}

fn validate_authenticated_endpoint(endpoint: &Url, network: Network) -> Result<()> {
    if !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || endpoint.host().is_none()
        || !matches!(endpoint.path(), "" | "/")
        || endpoint.port_or_known_default().and_then(NonZeroU16::new).is_none()
        || endpoint.as_str().len() > 2_048
    {
        return Err(ConfigError::Invalid("Comet endpoint contains forbidden URL components"));
    }
    match endpoint.scheme() {
        "https" => Ok(()),
        "http" if network == Network::Regtest => match endpoint.host() {
            Some(Host::Ipv4(address)) if IpAddr::V4(address).is_loopback() => Ok(()),
            Some(Host::Ipv6(address)) if IpAddr::V6(address).is_loopback() => Ok(()),
            _ => Err(ConfigError::Invalid(
                "regtest HTTP Comet endpoint must be literal loopback",
            )),
        },
        _ => Err(ConfigError::Invalid(
            "Comet endpoints require HTTPS except literal-loopback regtest",
        )),
    }
}

fn map_ledger_paths(raw: RawLedgerPaths) -> Result<RuntimePaths> {
    let data_dir = absolute_path(&raw.data_dir)?;
    let control_dir = absolute_path(&raw.control_dir)?;
    let control_socket = absolute_path(&raw.control_socket)?;
    let service_db = absolute_path(&raw.application_db)?;
    require_descendant(&data_dir, &service_db)?;
    require_descendant(&control_dir, &control_socket)?;
    Ok(RuntimePaths {
        data_dir,
        control_dir,
        control_socket,
        service_db,
        vault_file: None,
        vault_password_file: None,
        vault_checkpoint_provider: None,
        trust_coordinator_db: None,
        trust_checkpoint_provider: None,
        trust_root_light_block: None,
        bitcoin_cookie_file: map_secret_reference(raw.bitcoin_cookie_file)?,
        committee_descriptor: map_public_reference(raw.committee_descriptor)?,
        anchor_suite_registry: map_public_reference(raw.anchor_suite_registry)?,
        profile_manifest: map_public_reference(raw.profile_manifest)?,
        comet_tls: None,
    })
}

fn map_role_paths(raw: RawRolePaths) -> Result<RuntimePaths> {
    let data_dir = absolute_path(&raw.data_dir)?;
    let control_dir = absolute_path(&raw.control_dir)?;
    let control_socket = absolute_path(&raw.control_socket)?;
    let service_db = absolute_path(&raw.service_db)?;
    let vault_file = absolute_path(&raw.vault_file)?;
    let trust_coordinator_db = absolute_path(&raw.trust_coordinator_db)?;
    for path in [&service_db, &vault_file, &trust_coordinator_db] {
        require_descendant(&data_dir, path)?;
    }
    require_descendant(&control_dir, &control_socket)?;
    Ok(RuntimePaths {
        data_dir,
        control_dir,
        control_socket,
        service_db,
        vault_file: Some(vault_file),
        vault_password_file: Some(map_secret_reference(raw.vault_password_file)?),
        vault_checkpoint_provider: Some(map_checkpoint_provider(raw.vault_checkpoint_provider)?),
        trust_coordinator_db: Some(trust_coordinator_db),
        trust_checkpoint_provider: Some(map_checkpoint_provider(raw.trust_checkpoint_provider)?),
        trust_root_light_block: Some(map_public_reference(raw.trust_root_light_block)?),
        bitcoin_cookie_file: map_secret_reference(raw.bitcoin_cookie_file)?,
        committee_descriptor: map_public_reference(raw.committee_descriptor)?,
        anchor_suite_registry: map_public_reference(raw.anchor_suite_registry)?,
        profile_manifest: map_public_reference(raw.profile_manifest)?,
        comet_tls: raw.comet_tls.map(map_comet_tls).transpose()?,
    })
}

fn map_comet_tls(raw: RawCometTlsReferences) -> Result<CometTlsReferences> {
    if raw.ca_certificates.is_empty() || raw.ca_certificates.len() > 8 {
        return Err(ConfigError::Invalid("Comet CA certificate count is outside bounds"));
    }
    let ca_certificates = raw
        .ca_certificates
        .into_iter()
        .map(map_public_reference)
        .collect::<Result<Vec<_>>>()?;
    if ca_certificates.iter().enumerate().any(|(index, reference)| {
        ca_certificates
            .iter()
            .skip(index + 1)
            .any(|other| reference.path == other.path || reference.digest == other.digest)
    }) {
        return Err(ConfigError::Invalid("Comet CA certificate pins must be distinct"));
    }
    Ok(CometTlsReferences {
        ca_certificates,
        client_certificate_file: map_secret_reference(raw.client_certificate_file)?,
        client_private_key_file: map_secret_reference(raw.client_private_key_file)?,
    })
}

fn map_public_reference(raw: RawPublicFileReference) -> Result<ExternalFileReference> {
    Ok(ExternalFileReference {
        path: absolute_path(&raw.path)?,
        digest: require_hex32(&raw.sha256, true, "external reference digest")?,
    })
}

fn map_secret_reference(raw: RawSecretFileReference) -> Result<SecretFileReference> {
    Ok(SecretFileReference {
        path: absolute_path(&raw.path)?,
    })
}

fn map_checkpoint_provider(raw: RawCheckpointProviderReference) -> Result<ExternalCheckpointProviderRequirement> {
    let manifest = ExternalFileReference {
        path: absolute_path(&raw.manifest_path)?,
        digest: require_hex32(&raw.manifest_sha256, true, "checkpoint provider manifest")?,
    };
    Ok(ExternalCheckpointProviderRequirement {
        manifest,
        required_provider_id: require_hex32(&raw.required_provider_id, true, "checkpoint provider id")?,
        required_trust_domain_id: require_hex32(&raw.required_trust_domain_id, true, "checkpoint trust-domain id")?,
        policy_profile_id: require_hex32(&raw.policy_profile_id, true, "checkpoint policy profile")?,
    })
}

fn absolute_path(raw: &str) -> Result<PathBuf> {
    let path = PathBuf::from(raw);
    if raw.is_empty()
        || !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(ConfigError::UnsafePath(
            "path must be absolute and lexically normalized",
        ));
    }
    Ok(path)
}

fn require_descendant(parent: &Path, child: &Path) -> Result<()> {
    if child == parent || !child.starts_with(parent) {
        return Err(ConfigError::UnsafePath(
            "runtime file is outside its owner-controlled directory",
        ));
    }
    Ok(())
}

fn validate_distinct_writable_paths(paths: &RuntimePaths) -> Result<()> {
    let writable = paths.writable_paths();
    for (index, path) in writable.iter().enumerate() {
        if writable.iter().skip(index + 1).any(|other| path == other) {
            return Err(ConfigError::UnsafePath("writable runtime paths must be distinct"));
        }
    }
    let mut secret_and_external = vec![paths.bitcoin_cookie_file.path.as_path()];
    secret_and_external.extend(paths.vault_password_file.as_ref().map(|value| value.path.as_path()));
    secret_and_external.push(paths.committee_descriptor.path.as_path());
    secret_and_external.push(paths.anchor_suite_registry.path.as_path());
    secret_and_external.push(paths.profile_manifest.path.as_path());
    secret_and_external.extend(
        paths
            .vault_checkpoint_provider
            .as_ref()
            .map(|value| value.manifest.path.as_path()),
    );
    secret_and_external.extend(
        paths
            .trust_checkpoint_provider
            .as_ref()
            .map(|value| value.manifest.path.as_path()),
    );
    secret_and_external.extend(paths.trust_root_light_block.as_ref().map(|value| value.path.as_path()));
    if let Some(tls) = &paths.comet_tls {
        secret_and_external.extend(tls.ca_certificates.iter().map(|value| value.path.as_path()));
        secret_and_external.push(tls.client_certificate_file.path.as_path());
        secret_and_external.push(tls.client_private_key_file.path.as_path());
    }
    for (index, path) in secret_and_external.iter().enumerate() {
        if secret_and_external.iter().skip(index + 1).any(|other| path == other) {
            return Err(ConfigError::UnsafePath("owner-only references must use distinct files"));
        }
    }
    if secret_and_external
        .iter()
        .any(|path| writable.iter().any(|writable_path| paths_overlap(path, writable_path)))
    {
        return Err(ConfigError::UnsafePath("reference and writable paths must not overlap"));
    }
    let checkpoint_identities = paths.checkpoint_identities();
    if checkpoint_identities.len() == 2
        && (checkpoint_identities[0].0 == checkpoint_identities[1].0
            || checkpoint_identities[0].1 == checkpoint_identities[1].1)
    {
        return Err(ConfigError::Invalid(
            "vault and Comet checkpoints require distinct externally provisioned provider identities",
        ));
    }
    Ok(())
}

fn paths_overlap(first: &Path, second: &Path) -> bool {
    first == second || first.starts_with(second) || second.starts_with(first)
}

fn channel_template(identity: &DeploymentIdentity) -> Result<ChannelBindingV2> {
    let funding = FundingOutpointV2::new([0x01; 32], 0).map_err(|_| ConfigError::PolicyRejected)?;
    ChannelBindingV2::new(
        identity.protocol_suite_id.clone(),
        identity.network,
        identity.bitcoin_genesis_hash.clone(),
        &identity.deployment_id,
        funding,
        identity.committee_epoch,
        identity.committee_descriptor_digest.clone(),
        identity.anchor_parameter_suite_id.clone(),
    )
    .map_err(|_| ConfigError::PolicyRejected)
}

fn duration_ms(value: u64) -> Result<Duration> {
    if value == 0 {
        return Err(ConfigError::Invalid("duration must be positive"));
    }
    Ok(Duration::from_millis(value))
}

fn duration_seconds(value: u64) -> Result<Duration> {
    if value == 0 {
        return Err(ConfigError::Invalid("duration must be positive"));
    }
    Ok(Duration::from_secs(value))
}

fn decode_hex(value: &str, min_bytes: usize, max_bytes: usize) -> Result<Vec<u8>> {
    let min_len = min_bytes
        .checked_mul(2)
        .ok_or(ConfigError::Invalid("hex bound overflow"))?;
    let max_len = max_bytes
        .checked_mul(2)
        .ok_or(ConfigError::Invalid("hex bound overflow"))?;
    if value.len() < min_len
        || value.len() > max_len
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ConfigError::Invalid("hexadecimal field is not canonical"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or(ConfigError::Invalid("invalid hexadecimal digit"))?;
            let low = hex_nibble(pair[1]).ok_or(ConfigError::Invalid("invalid hexadecimal digit"))?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn require_hex32(value: &str, nonzero: bool, _field: &'static str) -> Result<[u8; 32]> {
    let decoded = decode_hex(value, 32, 32)?;
    let array: [u8; 32] = decoded
        .try_into()
        .map_err(|_| ConfigError::Invalid("32-byte identifier has wrong size"))?;
    if nonzero && array == [0_u8; 32] {
        return Err(ConfigError::Invalid("identifier must be nonzero"));
    }
    Ok(array)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn derive_id(domain: &[u8], source_digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(source_digest);
    hasher.finalize().into()
}

fn derive_finality_profile_id(domain: &[u8], manifest_digest: &[u8; 32], policy_digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(manifest_digest);
    hasher.update(policy_digest);
    hasher.finalize().into()
}

fn comet_policy_digest(raw: &RawComet, identity: &DeploymentIdentity, paths: &RuntimePaths) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(b"bitcoin-thunderbolt/runtime-config/comet-policy/v2");
    append(&mut hasher, identity.ledger_chain_id.as_bytes());
    hasher.update(THUNDERBOLT_APP_VERSION_V2.to_be_bytes());
    hasher.update(raw.source_version.to_be_bytes());
    append_comet_peer_policy(&mut hasher, 0, &raw.primary, identity.network)?;
    hasher.update(
        u64::try_from(raw.witnesses.len())
            .map_err(|_| ConfigError::Invalid("witness count exceeds u64"))?
            .to_be_bytes(),
    );
    for (index, peer) in raw.witnesses.iter().enumerate() {
        append_comet_peer_policy(
            &mut hasher,
            u64::try_from(index)
                .map_err(|_| ConfigError::Invalid("witness index exceeds u64"))?
                .checked_add(1)
                .ok_or(ConfigError::Invalid("witness index overflows"))?,
            peer,
            identity.network,
        )?;
    }
    hasher.update(raw.trust_root_height.to_be_bytes());
    hasher.update(require_hex32(
        &raw.trust_root_header_hash,
        true,
        "Comet trust-root hash",
    )?);
    for value in [
        raw.trusting_period_seconds,
        raw.clock_drift_ms,
        usize_u64(raw.max_validators)?,
        usize_u64(raw.max_adjacent_headers)?,
        usize_u64(raw.min_witnesses)?,
        usize_u64(raw.max_witnesses)?,
        raw.busy_timeout_ms,
        usize_u64(raw.max_trace_encoded_bytes)?,
        usize_u64(raw.max_execution_encoded_bytes)?,
        usize_u64(raw.max_proof_bundle_bytes)?,
        raw.operation_timeout_ms,
        usize_u64(raw.history_max_transitions)?,
        usize_u64(raw.history_max_proof_bytes)?,
        usize_u64(raw.history_max_requests)?,
        usize_u64(raw.rpc_response_bytes)?,
        usize_u64(raw.rpc_aggregate_bytes)?,
        u64::from(raw.rpc_retry_attempts),
        raw.rpc_retry_base_delay_ms,
        u64::from(raw.rpc_validator_page_size),
        usize_u64(raw.rpc_max_headers)?,
        usize_u64(raw.rpc_max_header_bytes)?,
    ] {
        hasher.update(value.to_be_bytes());
    }
    match &paths.comet_tls {
        Some(tls) => {
            hasher.update([1]);
            hasher.update(
                u64::try_from(tls.ca_certificates.len())
                    .map_err(|_| ConfigError::Invalid("CA count exceeds u64"))?
                    .to_be_bytes(),
            );
            for certificate in &tls.ca_certificates {
                hasher.update(certificate.digest);
            }
        }
        None => hasher.update([0]),
    }
    Ok(hasher.finalize().into())
}

fn append_comet_peer_policy(hasher: &mut Sha256, position: u64, raw: &RawCometPeer, network: Network) -> Result<()> {
    let endpoint = Url::parse(&raw.endpoint).map_err(|_| ConfigError::Invalid("Comet endpoint URL is invalid"))?;
    validate_authenticated_endpoint(&endpoint, network)?;
    hasher.update(position.to_be_bytes());
    append(hasher, endpoint.as_str().as_bytes());
    hasher.update(decode_hex(&raw.node_id, 20, 20)?);
    hasher.update(require_hex32(
        &raw.transport_binding_sha256,
        true,
        "Comet transport binding",
    )?);
    Ok(())
}

fn usize_u64(value: usize) -> Result<u64> {
    u64::try_from(value).map_err(|_| ConfigError::Invalid("policy value exceeds u64"))
}

fn deployment_descriptor_digest(identity: &DeploymentIdentity) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"bitcoin-thunderbolt/runtime-config/deployment-descriptor/v2");
    hasher.update([network_tag(identity.network)]);
    append(&mut hasher, identity.ledger_chain_id.as_bytes());
    append(&mut hasher, &identity.deployment_id);
    append(&mut hasher, identity.protocol_suite_id.as_bytes());
    append(&mut hasher, identity.bitcoin_genesis_hash.as_bytes());
    hasher.update(identity.committee_epoch.to_be_bytes());
    append(&mut hasher, identity.committee_descriptor_digest.as_bytes());
    append(&mut hasher, identity.anchor_parameter_suite_id.as_bytes());
    hasher.finalize().into()
}

fn append(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
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

fn reject_secret_keys(value: &Value) -> Result<()> {
    match value {
        Value::Table(table) => {
            for (key, child) in table {
                let normalized = key.to_ascii_lowercase().replace('-', "_");
                let allowed_reference = matches!(
                    normalized.as_str(),
                    "vault_password_file" | "bitcoin_cookie_file" | "client_private_key_file"
                );
                if !allowed_reference
                    && [
                        "password",
                        "secret",
                        "token",
                        "private_key",
                        "mnemonic",
                        "seed",
                        "credential",
                        "authorization",
                        "api_key",
                        "cookie_value",
                    ]
                    .iter()
                    .any(|forbidden| normalized.contains(forbidden))
                {
                    return Err(ConfigError::SecretValueForbidden);
                }
                reject_secret_keys(child)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                reject_secret_keys(child)?;
            }
        }
        Value::String(_) | Value::Integer(_) | Value::Float(_) | Value::Boolean(_) | Value::Datetime(_) => {}
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ConfiguredVerifierIdentity {
    verifier_profile_id: [u8; 32],
    deployment_descriptor: [u8; 32],
}

impl StaticAdmissionVerifierV2 for ConfiguredVerifierIdentity {
    type Error = ();

    fn verifier_profile_id(&self) -> [u8; 32] {
        self.verifier_profile_id
    }

    fn deployment_descriptor(&self) -> [u8; 32] {
        self.deployment_descriptor
    }

    fn verify_static(&self, _request: StaticAdmissionRequestV2<'_>) -> std::result::Result<(), Self::Error> {
        Err(())
    }
}
