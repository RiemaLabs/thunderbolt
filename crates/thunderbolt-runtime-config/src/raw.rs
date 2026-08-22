use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(crate) struct RawDocument {
    pub(crate) config_version: u16,
    #[serde(flatten)]
    pub(crate) process: RawProcess,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub(crate) enum RawProcess {
    Ledger(RawLedgerProcess),
    Holder(RawHolderProcess),
    Committee(RawCommitteeProcess),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawLedgerProcess {
    pub(crate) identity: RawIdentity,
    pub(crate) capabilities: RawCapabilities,
    pub(crate) paths: RawLedgerPaths,
    pub(crate) control: RawControl,
    pub(crate) bitcoin: RawBitcoin,
    pub(crate) application: RawApplication,
    pub(crate) abci: RawAbci,
    pub(crate) ledger_profiles: RawLedgerProfiles,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawHolderProcess {
    pub(crate) identity: RawIdentity,
    pub(crate) capabilities: RawCapabilities,
    pub(crate) paths: RawRolePaths,
    pub(crate) control: RawControl,
    pub(crate) bitcoin: RawBitcoin,
    pub(crate) comet: RawComet,
    pub(crate) holder: RawHolder,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawCommitteeProcess {
    pub(crate) identity: RawIdentity,
    pub(crate) capabilities: RawCapabilities,
    pub(crate) paths: RawRolePaths,
    pub(crate) control: RawControl,
    pub(crate) bitcoin: RawBitcoin,
    pub(crate) comet: RawComet,
    pub(crate) committee: RawCommittee,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawIdentity {
    pub(crate) network: RawNetwork,
    pub(crate) ledger_chain_id: String,
    pub(crate) deployment_id_hex: String,
    pub(crate) protocol_suite_id: String,
    pub(crate) bitcoin_genesis_hash: String,
    pub(crate) committee_epoch: u64,
    pub(crate) committee_descriptor_digest: String,
    pub(crate) anchor_parameter_suite_id: String,
    pub(crate) runtime_profile_id: String,
    pub(crate) finality_verifier_profile_id: String,
    pub(crate) finality_policy_digest: String,
    pub(crate) application_version: u64,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RawNetwork {
    Regtest,
    Signet,
    Testnet3,
    Testnet4,
    Mainnet,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RawDeploymentMode {
    NonProduction,
    Production,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RawSigningMode {
    Unavailable,
    Production,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RawPaillierProfile {
    LegacyRc2048V1,
    ProtocolV2Production3072,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawCapabilities {
    pub(crate) deployment_mode: RawDeploymentMode,
    pub(crate) holder_signing: RawSigningMode,
    pub(crate) committee_threshold_signing: RawSigningMode,
    pub(crate) paillier_profile: RawPaillierProfile,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawPublicFileReference {
    pub(crate) path: String,
    pub(crate) sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawSecretFileReference {
    pub(crate) path: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawCheckpointProviderReference {
    pub(crate) manifest_path: String,
    pub(crate) manifest_sha256: String,
    pub(crate) required_provider_id: String,
    pub(crate) required_trust_domain_id: String,
    pub(crate) policy_profile_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawCometTlsReferences {
    pub(crate) ca_certificates: Vec<RawPublicFileReference>,
    pub(crate) client_certificate_file: RawSecretFileReference,
    pub(crate) client_private_key_file: RawSecretFileReference,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawLedgerPaths {
    pub(crate) data_dir: String,
    pub(crate) control_dir: String,
    pub(crate) control_socket: String,
    pub(crate) application_db: String,
    pub(crate) bitcoin_cookie_file: RawSecretFileReference,
    pub(crate) committee_descriptor: RawPublicFileReference,
    pub(crate) anchor_suite_registry: RawPublicFileReference,
    pub(crate) profile_manifest: RawPublicFileReference,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawRolePaths {
    pub(crate) data_dir: String,
    pub(crate) control_dir: String,
    pub(crate) control_socket: String,
    pub(crate) service_db: String,
    pub(crate) vault_file: String,
    pub(crate) vault_password_file: RawSecretFileReference,
    pub(crate) vault_checkpoint_provider: RawCheckpointProviderReference,
    pub(crate) trust_coordinator_db: String,
    pub(crate) trust_checkpoint_provider: RawCheckpointProviderReference,
    pub(crate) trust_root_light_block: RawPublicFileReference,
    pub(crate) bitcoin_cookie_file: RawSecretFileReference,
    pub(crate) committee_descriptor: RawPublicFileReference,
    pub(crate) anchor_suite_registry: RawPublicFileReference,
    pub(crate) profile_manifest: RawPublicFileReference,
    pub(crate) comet_tls: Option<RawCometTlsReferences>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawBitcoin {
    pub(crate) endpoint: String,
    pub(crate) request_timeout_ms: u64,
    pub(crate) connect_timeout_ms: u64,
    pub(crate) retry_delay_ms: u64,
    pub(crate) max_request_bytes: usize,
    pub(crate) max_response_bytes: usize,
    pub(crate) read_attempts: u8,
    pub(crate) max_chain_sync_blocks: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawControl {
    pub(crate) max_frame_bytes: usize,
    pub(crate) max_concurrent_requests: usize,
    pub(crate) max_inflight_bytes: usize,
    pub(crate) io_timeout_ms: u64,
    pub(crate) handler_timeout_ms: u64,
    pub(crate) shutdown_grace_ms: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawApplication {
    pub(crate) busy_timeout_ms: u64,
    pub(crate) max_entries_per_channel: u64,
    pub(crate) max_pending_invoices: usize,
    pub(crate) max_invoice_ttl_ms: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawLedgerProfiles {
    pub(crate) static_verifier_profile_id: String,
    pub(crate) deployment_descriptor_digest: String,
    pub(crate) consensus_profile_digest: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawAbci {
    pub(crate) bind_address: String,
    pub(crate) max_frame_bytes: usize,
    pub(crate) mempool_max_transactions: usize,
    pub(crate) mempool_max_bytes: usize,
    pub(crate) admission_requests_per_second: u32,
    pub(crate) max_connections: u16,
    pub(crate) minimum_fee: u64,
    pub(crate) fatal_exit_code: u8,
    pub(crate) supervisor_max_restarts: u16,
    pub(crate) supervisor_window_seconds: u64,
    pub(crate) supervisor_backoff_ms: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawHolder {
    pub(crate) retry_initial_delay_ms: u64,
    pub(crate) retry_maximum_delay_ms: u64,
    pub(crate) retry_maximum_attempts: u32,
    pub(crate) submit_batch: usize,
    pub(crate) finality_batch: usize,
    pub(crate) busy_timeout_ms: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawCommittee {
    pub(crate) member_id: u32,
    pub(crate) max_inbox_rows: u32,
    pub(crate) max_outbox_rows: u32,
    pub(crate) fetch_batch_size: u16,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawCometPeer {
    pub(crate) endpoint: String,
    pub(crate) node_id: String,
    pub(crate) transport_binding_sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawComet {
    pub(crate) coordinator_identity: String,
    pub(crate) source_version: u64,
    pub(crate) primary: RawCometPeer,
    pub(crate) witnesses: Vec<RawCometPeer>,
    pub(crate) trust_root_height: u64,
    pub(crate) trust_root_header_hash: String,
    pub(crate) trusting_period_seconds: u64,
    pub(crate) clock_drift_ms: u64,
    pub(crate) max_validators: usize,
    pub(crate) max_adjacent_headers: usize,
    pub(crate) min_witnesses: usize,
    pub(crate) max_witnesses: usize,
    pub(crate) busy_timeout_ms: u64,
    pub(crate) max_trace_encoded_bytes: usize,
    pub(crate) max_execution_encoded_bytes: usize,
    pub(crate) max_proof_bundle_bytes: usize,
    pub(crate) operation_timeout_ms: u64,
    pub(crate) history_max_transitions: usize,
    pub(crate) history_max_proof_bytes: usize,
    pub(crate) history_max_requests: usize,
    pub(crate) rpc_response_bytes: usize,
    pub(crate) rpc_aggregate_bytes: usize,
    pub(crate) rpc_retry_attempts: u8,
    pub(crate) rpc_retry_base_delay_ms: u64,
    pub(crate) rpc_validator_page_size: u8,
    pub(crate) rpc_max_headers: usize,
    pub(crate) rpc_max_header_bytes: usize,
}
