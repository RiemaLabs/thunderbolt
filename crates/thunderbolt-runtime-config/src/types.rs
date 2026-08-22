use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bitcoin::Network;
use rustls::pki_types::CertificateDer;
use serde::Serialize;
use thunderbolt_bitcoin::RpcConfig;
use thunderbolt_cometbft_client::{CoordinatorConfig, PeerIdentity};
use thunderbolt_cometbft_rpc::{
    CometBftRpcTransport, HttpsPeer, LoopbackHttpPeer, OwnerOnlyPemClientIdentity, RetryPolicy as CometRpcRetryPolicy,
    RpcLimits, RpcPeer, RpcTransportConfig,
};
use thunderbolt_committee::CommitteeMemberId;
use thunderbolt_committee_node::NodeConfig as CommitteeNodeConfig;
use thunderbolt_control::ControlServerConfig;
use thunderbolt_holder_node::HolderNodeConfig;
use thunderbolt_ledger::LedgerChainIdV2;
use thunderbolt_ledger_abci::ConsensusProfileV2;
use thunderbolt_ledger_app::ApplicationOptions;
use thunderbolt_wire::{
    AnchorParameterSuiteIdV2, BitcoinGenesisHashV2, CommitteeDescriptorDigestV2, ProtocolSuiteIdV2,
};
use url::Url;

use crate::{ConfigError, Result};

/// Only accepted operator-document version.
pub const CONFIG_VERSION_V2: u16 = 2;

/// Process role selected by one configuration document.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeRole {
    /// Replicated Ledger application and ABCI process.
    Ledger,
    /// Holder client/service process.
    Holder,
    /// One-member Committee process.
    Committee,
}

/// Common immutable deployment identity shared by every role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeploymentIdentity {
    pub(crate) network: Network,
    pub(crate) ledger_chain_id: LedgerChainIdV2,
    pub(crate) deployment_id: Vec<u8>,
    pub(crate) protocol_suite_id: ProtocolSuiteIdV2,
    pub(crate) bitcoin_genesis_hash: BitcoinGenesisHashV2,
    pub(crate) committee_epoch: u64,
    pub(crate) committee_descriptor_digest: CommitteeDescriptorDigestV2,
    pub(crate) anchor_parameter_suite_id: AnchorParameterSuiteIdV2,
    pub(crate) runtime_profile_id: [u8; 32],
    pub(crate) finality_verifier_profile_id: [u8; 32],
    pub(crate) finality_policy_digest: [u8; 32],
    pub(crate) profile_manifest_digest: [u8; 32],
}

#[allow(missing_docs)]
impl DeploymentIdentity {
    /// Returns the exact Bitcoin network.
    pub const fn network(&self) -> Network {
        self.network
    }

    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    pub fn deployment_id(&self) -> &[u8] {
        &self.deployment_id
    }

    pub const fn protocol_suite_id(&self) -> &ProtocolSuiteIdV2 {
        &self.protocol_suite_id
    }

    pub const fn bitcoin_genesis_hash(&self) -> &BitcoinGenesisHashV2 {
        &self.bitcoin_genesis_hash
    }

    pub const fn committee_epoch(&self) -> u64 {
        self.committee_epoch
    }

    pub const fn committee_descriptor_digest(&self) -> &CommitteeDescriptorDigestV2 {
        &self.committee_descriptor_digest
    }

    pub const fn anchor_parameter_suite_id(&self) -> &AnchorParameterSuiteIdV2 {
        &self.anchor_parameter_suite_id
    }

    pub const fn runtime_profile_id(&self) -> &[u8; 32] {
        &self.runtime_profile_id
    }

    pub const fn finality_verifier_profile_id(&self) -> &[u8; 32] {
        &self.finality_verifier_profile_id
    }

    /// Returns the canonical digest of the exact Comet/finality policy.
    pub const fn finality_policy_digest(&self) -> &[u8; 32] {
        &self.finality_policy_digest
    }
}

/// Immutable public file reference with an expected exact SHA-256 digest.
#[derive(Clone, PartialEq, Eq)]
pub struct ExternalFileReference {
    pub(crate) path: PathBuf,
    pub(crate) digest: [u8; 32],
}

#[allow(missing_docs)]
impl ExternalFileReference {
    /// Returns the absolute owner-only path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn sha256(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Reopens with no-follow/owner checks and returns only bytes matching the
    /// pinned digest.
    pub fn read_verified(&self) -> Result<Vec<u8>> {
        crate::validate::read_external_reference(self)
    }
}

impl fmt::Debug for ExternalFileReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExternalFileReference")
            .field("path", &"<owner-only-path>")
            .field("sha256", &crate::mapping::hex_encode(&self.digest))
            .finish()
    }
}

/// Owner-only secret-provider file reference. Contents are never loaded or
/// represented by this crate.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretFileReference {
    pub(crate) path: PathBuf,
}

/// Required identity for an externally provisioned checkpoint capability.
///
/// The manifest is configuration metadata, never checkpoint state and never
/// proof of independence. Readiness remains false until a trusted capability
/// reporting these exact externally assigned identities is injected.
#[derive(Clone, PartialEq, Eq)]
pub struct ExternalCheckpointProviderRequirement {
    pub(crate) manifest: ExternalFileReference,
    pub(crate) required_provider_id: [u8; 32],
    pub(crate) required_trust_domain_id: [u8; 32],
    pub(crate) policy_profile_id: [u8; 32],
}

/// Trusted external checkpoint capability identity boundary.
pub trait CheckpointProviderCapability {
    /// Returns the stable provider instance identity.
    fn provider_id(&self) -> [u8; 32];
    /// Returns the independently provisioned trust-domain identity.
    fn trust_domain_id(&self) -> [u8; 32];
    /// Returns the runtime/finality policy profile implemented by the provider.
    fn policy_profile_id(&self) -> [u8; 32];
}

/// Explicit CA and owner-only client-identity references required by HTTPS
/// Comet peers. Private key bytes never enter this crate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CometTlsReferences {
    pub(crate) ca_certificates: Vec<ExternalFileReference>,
    pub(crate) client_certificate_file: SecretFileReference,
    pub(crate) client_private_key_file: SecretFileReference,
}

impl CometTlsReferences {
    /// Returns one to eight pinned CA certificate files.
    pub fn ca_certificates(&self) -> &[ExternalFileReference] {
        &self.ca_certificates
    }

    /// Returns the owner-only client certificate path.
    pub const fn client_certificate_file(&self) -> &SecretFileReference {
        &self.client_certificate_file
    }

    /// Returns the owner-only client private-key path.
    pub const fn client_private_key_file(&self) -> &SecretFileReference {
        &self.client_private_key_file
    }

    /// Reopens, rehashes and parses the exact CA and client-identity material
    /// for immediate use with `HttpsPeer::new`.
    pub fn load_for_handoff(&self) -> Result<LoadedCometTls> {
        let (ca_certificates, client_identity) = crate::validate::load_comet_tls(self)?;
        Ok(LoadedCometTls {
            ca_certificates,
            client_identity,
        })
    }
}

/// Constructor-ready TLS material loaded only at a revalidated handoff.
pub struct LoadedCometTls {
    ca_certificates: Vec<CertificateDer<'static>>,
    client_identity: OwnerOnlyPemClientIdentity,
}

impl LoadedCometTls {
    /// Returns parsed CA certificates accepted by `HttpsPeer::new`.
    pub fn ca_certificates(&self) -> &[CertificateDer<'static>] {
        &self.ca_certificates
    }

    /// Returns the redacted owner-only client identity provider.
    pub const fn client_identity(&self) -> &OwnerOnlyPemClientIdentity {
        &self.client_identity
    }
}

impl fmt::Debug for LoadedCometTls {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoadedCometTls")
            .field("ca_certificates", &self.ca_certificates.len())
            .field("client_identity", &"<redacted>")
            .finish()
    }
}

#[allow(missing_docs)]
impl ExternalCheckpointProviderRequirement {
    /// Returns the pinned external provider manifest.
    pub const fn manifest(&self) -> &ExternalFileReference {
        &self.manifest
    }

    pub const fn required_provider_id(&self) -> &[u8; 32] {
        &self.required_provider_id
    }

    pub const fn required_trust_domain_id(&self) -> &[u8; 32] {
        &self.required_trust_domain_id
    }

    pub const fn policy_profile_id(&self) -> &[u8; 32] {
        &self.policy_profile_id
    }

    /// Checks an injected external capability against every pinned identity.
    pub fn accepts<C: CheckpointProviderCapability>(&self, capability: &C) -> bool {
        capability.provider_id() == self.required_provider_id
            && capability.trust_domain_id() == self.required_trust_domain_id
            && capability.policy_profile_id() == self.policy_profile_id
    }
}

impl fmt::Debug for ExternalCheckpointProviderRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExternalCheckpointProviderRequirement")
            .field("manifest", &self.manifest)
            .field(
                "required_provider_id",
                &crate::mapping::hex_encode(&self.required_provider_id),
            )
            .field(
                "required_trust_domain_id",
                &crate::mapping::hex_encode(&self.required_trust_domain_id),
            )
            .field(
                "policy_profile_id",
                &crate::mapping::hex_encode(&self.policy_profile_id),
            )
            .finish()
    }
}

impl SecretFileReference {
    /// Returns the absolute owner-only provider path without reading it.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reopens the owner-only secret provider without following symlinks.
    pub fn open_owner_only(&self) -> Result<std::fs::File> {
        crate::validate::open_secret_reference(&self.path)
    }
}

impl fmt::Debug for SecretFileReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SecretFileReference")
            .field(&"<redacted>")
            .finish()
    }
}

/// Filesystem layout audited immediately before policy handoff.
#[derive(Clone, PartialEq, Eq)]
pub struct RuntimePaths {
    pub(crate) data_dir: PathBuf,
    pub(crate) control_dir: PathBuf,
    pub(crate) control_socket: PathBuf,
    pub(crate) service_db: PathBuf,
    pub(crate) vault_file: Option<PathBuf>,
    pub(crate) vault_password_file: Option<SecretFileReference>,
    pub(crate) vault_checkpoint_provider: Option<ExternalCheckpointProviderRequirement>,
    pub(crate) trust_coordinator_db: Option<PathBuf>,
    pub(crate) trust_checkpoint_provider: Option<ExternalCheckpointProviderRequirement>,
    pub(crate) trust_root_light_block: Option<ExternalFileReference>,
    pub(crate) bitcoin_cookie_file: SecretFileReference,
    pub(crate) committee_descriptor: ExternalFileReference,
    pub(crate) anchor_suite_registry: ExternalFileReference,
    pub(crate) profile_manifest: ExternalFileReference,
    pub(crate) comet_tls: Option<CometTlsReferences>,
}

#[allow(missing_docs)]
impl RuntimePaths {
    /// Returns the owner-only process data directory.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn control_dir(&self) -> &Path {
        &self.control_dir
    }

    pub fn control_socket(&self) -> &Path {
        &self.control_socket
    }

    pub fn service_db(&self) -> &Path {
        &self.service_db
    }

    pub fn vault_file(&self) -> Option<&Path> {
        self.vault_file.as_deref()
    }

    pub const fn vault_password_file(&self) -> Option<&SecretFileReference> {
        self.vault_password_file.as_ref()
    }

    pub const fn vault_checkpoint_provider(&self) -> Option<&ExternalCheckpointProviderRequirement> {
        self.vault_checkpoint_provider.as_ref()
    }

    pub fn trust_coordinator_db(&self) -> Option<&Path> {
        self.trust_coordinator_db.as_deref()
    }

    pub const fn trust_checkpoint_provider(&self) -> Option<&ExternalCheckpointProviderRequirement> {
        self.trust_checkpoint_provider.as_ref()
    }

    pub const fn trust_root_light_block(&self) -> Option<&ExternalFileReference> {
        self.trust_root_light_block.as_ref()
    }

    pub const fn bitcoin_cookie_file(&self) -> &SecretFileReference {
        &self.bitcoin_cookie_file
    }

    pub const fn committee_descriptor(&self) -> &ExternalFileReference {
        &self.committee_descriptor
    }

    pub const fn anchor_suite_registry(&self) -> &ExternalFileReference {
        &self.anchor_suite_registry
    }

    pub const fn profile_manifest(&self) -> &ExternalFileReference {
        &self.profile_manifest
    }

    /// Returns HTTPS CA and client-identity references, absent only for the
    /// credential-free literal-loopback regtest profile.
    pub const fn comet_tls(&self) -> Option<&CometTlsReferences> {
        self.comet_tls.as_ref()
    }

    pub(crate) fn writable_paths(&self) -> Vec<&Path> {
        let mut paths = vec![
            self.data_dir.as_path(),
            self.control_dir.as_path(),
            self.control_socket.as_path(),
            self.service_db.as_path(),
        ];
        paths.extend(self.vault_file.as_deref());
        paths.extend(self.trust_coordinator_db.as_deref());
        paths
    }

    pub(crate) fn exclusive_reference_paths(&self) -> Vec<&Path> {
        let mut paths = Vec::new();
        paths.extend(self.vault_password_file.as_ref().map(|value| value.path.as_path()));
        paths.extend(
            self.vault_checkpoint_provider
                .as_ref()
                .map(|value| value.manifest.path.as_path()),
        );
        paths.extend(
            self.trust_checkpoint_provider
                .as_ref()
                .map(|value| value.manifest.path.as_path()),
        );
        if let Some(tls) = &self.comet_tls {
            paths.push(tls.client_certificate_file.path.as_path());
            paths.push(tls.client_private_key_file.path.as_path());
        }
        paths
    }

    pub(crate) fn all_reference_paths(&self) -> Vec<&Path> {
        let mut paths = vec![
            self.bitcoin_cookie_file.path.as_path(),
            self.committee_descriptor.path.as_path(),
            self.anchor_suite_registry.path.as_path(),
            self.profile_manifest.path.as_path(),
        ];
        paths.extend(self.vault_password_file.as_ref().map(|value| value.path.as_path()));
        paths.extend(
            self.vault_checkpoint_provider
                .as_ref()
                .map(|value| value.manifest.path.as_path()),
        );
        paths.extend(
            self.trust_checkpoint_provider
                .as_ref()
                .map(|value| value.manifest.path.as_path()),
        );
        paths.extend(self.trust_root_light_block.as_ref().map(|value| value.path.as_path()));
        if let Some(tls) = &self.comet_tls {
            paths.extend(tls.ca_certificates.iter().map(|value| value.path.as_path()));
            paths.push(tls.client_certificate_file.path.as_path());
            paths.push(tls.client_private_key_file.path.as_path());
        }
        paths
    }

    pub(crate) fn checkpoint_identities(&self) -> Vec<([u8; 32], [u8; 32])> {
        [
            self.vault_checkpoint_provider.as_ref(),
            self.trust_checkpoint_provider.as_ref(),
        ]
        .into_iter()
        .flatten()
        .map(|provider| (provider.required_provider_id, provider.required_trust_domain_id))
        .collect()
    }
}

impl fmt::Debug for RuntimePaths {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimePaths")
            .field("paths", &"<redacted>")
            .finish()
    }
}

/// Explicitly unavailable release capabilities. This configuration crate does
/// not turn missing signing or production Paillier implementations into live
/// capabilities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityBoundary;

#[allow(missing_docs)]
impl CapabilityBoundary {
    /// Reports that Holder signing is unavailable in this release profile.
    pub const fn holder_signing_available(self) -> bool {
        false
    }

    pub const fn committee_threshold_signing_available(self) -> bool {
        false
    }

    pub const fn production_paillier_3072_available(self) -> bool {
        false
    }

    /// Reports that external rollback/checkpoint providers still require injection.
    pub const fn external_checkpoint_providers_ready(self) -> bool {
        false
    }

    /// Reports that concrete authenticated Comet transport still requires handoff.
    pub const fn authenticated_comet_transport_ready(self) -> bool {
        false
    }
}

/// CometBFT endpoint and authenticated peer pin.
#[derive(Clone, PartialEq, Eq)]
pub struct CometPeerPolicy {
    pub(crate) endpoint: Url,
    pub(crate) identity: PeerIdentity,
}

impl fmt::Debug for CometPeerPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CometPeerPolicy")
            .field("endpoint", &"<redacted>")
            .field("identity", &self.identity)
            .finish()
    }
}

#[allow(missing_docs)]
impl CometPeerPolicy {
    /// Returns the credential-free authenticated RPC endpoint.
    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    pub const fn identity(&self) -> &PeerIdentity {
        &self.identity
    }
}

/// Exact out-of-band root pin. The referenced light block must still be parsed
/// and passed to `PinnedTrustRoot::new` by the finality integration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustRootReference {
    pub(crate) height: u64,
    pub(crate) header_hash: [u8; 32],
    pub(crate) light_block: ExternalFileReference,
}

#[allow(missing_docs)]
impl TrustRootReference {
    /// Returns the positive pinned Comet height.
    pub const fn height(&self) -> u64 {
        self.height
    }

    pub const fn header_hash(&self) -> &[u8; 32] {
        &self.header_hash
    }

    pub const fn light_block(&self) -> &ExternalFileReference {
        &self.light_block
    }
}

/// Authenticated transport policy surrounding the committed trust coordinator.
#[derive(Clone, Debug)]
pub struct CometRuntimePolicy {
    pub(crate) coordinator: CoordinatorConfig,
    pub(crate) primary: CometPeerPolicy,
    pub(crate) witnesses: Vec<CometPeerPolicy>,
    pub(crate) trust_root: TrustRootReference,
    pub(crate) rpc_limits: RpcLimits,
    pub(crate) rpc_retry: CometRpcRetryPolicy,
}

#[allow(missing_docs)]
impl CometRuntimePolicy {
    /// Returns the committed crash-safe coordinator policy.
    pub const fn coordinator(&self) -> &CoordinatorConfig {
        &self.coordinator
    }

    pub const fn primary(&self) -> &CometPeerPolicy {
        &self.primary
    }

    pub fn witnesses(&self) -> &[CometPeerPolicy] {
        &self.witnesses
    }

    pub const fn trust_root(&self) -> &TrustRootReference {
        &self.trust_root
    }

    /// Returns bounded Comet RPC response, trace, validator, and header limits.
    pub const fn rpc_limits(&self) -> RpcLimits {
        self.rpc_limits
    }

    /// Returns bounded idempotent RPC retry policy.
    pub const fn rpc_retry(&self) -> CometRpcRetryPolicy {
        self.rpc_retry
    }
}

/// Bounded ABCI listener, mempool, and supervisor policy. The ABCI crate does
/// not itself provide a production socket server, so this value is a required
/// boundary for an external reviewed dispatcher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbciRuntimePolicy {
    pub(crate) bind_address: SocketAddr,
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

#[allow(missing_docs)]
impl AbciRuntimePolicy {
    /// Returns the loopback-only ABCI bind address.
    pub const fn bind_address(&self) -> SocketAddr {
        self.bind_address
    }

    pub const fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }

    pub const fn mempool_max_transactions(&self) -> usize {
        self.mempool_max_transactions
    }

    pub const fn mempool_max_bytes(&self) -> usize {
        self.mempool_max_bytes
    }

    pub const fn admission_requests_per_second(&self) -> u32 {
        self.admission_requests_per_second
    }

    pub const fn max_connections(&self) -> u16 {
        self.max_connections
    }

    pub const fn minimum_fee(&self) -> u64 {
        self.minimum_fee
    }

    pub const fn fatal_exit_code(&self) -> u8 {
        self.fatal_exit_code
    }

    pub const fn supervisor_max_restarts(&self) -> u16 {
        self.supervisor_max_restarts
    }

    pub const fn supervisor_window_seconds(&self) -> u64 {
        self.supervisor_window_seconds
    }

    pub const fn supervisor_backoff_ms(&self) -> u64 {
        self.supervisor_backoff_ms
    }
}

/// Validated Ledger process policy. It intentionally contains no verifier or
/// daemon constructor because production proof verification is not committed.
#[derive(Clone)]
pub struct LedgerRuntimeConfig {
    pub(crate) identity: DeploymentIdentity,
    pub(crate) paths: RuntimePaths,
    pub(crate) application_options: ApplicationOptions,
    pub(crate) consensus_profile: ConsensusProfileV2,
    pub(crate) static_verifier_profile_id: [u8; 32],
    pub(crate) deployment_descriptor_digest: [u8; 32],
    pub(crate) abci: AbciRuntimePolicy,
    pub(crate) bitcoin: RpcConfig,
    pub(crate) control: ControlServerConfig,
    pub(crate) capabilities: CapabilityBoundary,
    pub(crate) filesystem_audit: Option<Arc<crate::validate::FilesystemAudit>>,
}

#[allow(missing_docs)]
impl LedgerRuntimeConfig {
    /// Returns the common deployment identity.
    pub const fn identity(&self) -> &DeploymentIdentity {
        &self.identity
    }

    pub const fn paths(&self) -> &RuntimePaths {
        &self.paths
    }

    pub fn application_options(&self) -> ApplicationOptions {
        self.application_options.clone()
    }

    pub const fn consensus_profile(&self) -> ConsensusProfileV2 {
        self.consensus_profile
    }

    pub const fn static_verifier_profile_id(&self) -> &[u8; 32] {
        &self.static_verifier_profile_id
    }

    pub const fn deployment_descriptor_digest(&self) -> &[u8; 32] {
        &self.deployment_descriptor_digest
    }

    pub const fn abci(&self) -> &AbciRuntimePolicy {
        &self.abci
    }

    pub const fn bitcoin_rpc(&self) -> &RpcConfig {
        &self.bitcoin
    }

    pub const fn control(&self) -> &ControlServerConfig {
        &self.control
    }
}

/// Validated Holder process policy. Concrete signers, finality transport,
/// settlement, threshold signing, and vault floor implementations remain
/// external fail-closed capabilities.
#[derive(Clone)]
pub struct HolderRuntimeConfig {
    pub(crate) identity: DeploymentIdentity,
    pub(crate) paths: RuntimePaths,
    pub(crate) node: HolderNodeConfig,
    pub(crate) comet: CometRuntimePolicy,
    pub(crate) bitcoin: RpcConfig,
    pub(crate) control: ControlServerConfig,
    pub(crate) capabilities: CapabilityBoundary,
    pub(crate) filesystem_audit: Option<Arc<crate::validate::FilesystemAudit>>,
}

#[allow(missing_docs)]
impl HolderRuntimeConfig {
    /// Returns the common deployment identity.
    pub const fn identity(&self) -> &DeploymentIdentity {
        &self.identity
    }

    pub const fn paths(&self) -> &RuntimePaths {
        &self.paths
    }

    pub const fn node(&self) -> &HolderNodeConfig {
        &self.node
    }

    pub const fn comet(&self) -> &CometRuntimePolicy {
        &self.comet
    }

    pub const fn bitcoin_rpc(&self) -> &RpcConfig {
        &self.bitcoin
    }

    pub const fn control(&self) -> &ControlServerConfig {
        &self.control
    }
}

/// Validated Committee process policy. Descriptor parsing, member package,
/// vault password, rollback-floor backend, finality verifier and signer are
/// deliberately not constructed here.
#[derive(Clone)]
pub struct CommitteeRuntimeConfig {
    pub(crate) identity: DeploymentIdentity,
    pub(crate) paths: RuntimePaths,
    pub(crate) node: CommitteeNodeConfig,
    pub(crate) member_id: CommitteeMemberId,
    pub(crate) comet: CometRuntimePolicy,
    pub(crate) bitcoin: RpcConfig,
    pub(crate) control: ControlServerConfig,
    pub(crate) capabilities: CapabilityBoundary,
    pub(crate) filesystem_audit: Option<Arc<crate::validate::FilesystemAudit>>,
}

#[allow(missing_docs)]
impl CommitteeRuntimeConfig {
    /// Returns the common deployment identity.
    pub const fn identity(&self) -> &DeploymentIdentity {
        &self.identity
    }

    pub const fn paths(&self) -> &RuntimePaths {
        &self.paths
    }

    pub const fn node(&self) -> &CommitteeNodeConfig {
        &self.node
    }

    pub const fn member_id(&self) -> CommitteeMemberId {
        self.member_id
    }

    pub const fn comet(&self) -> &CometRuntimePolicy {
        &self.comet
    }

    pub const fn bitcoin_rpc(&self) -> &RpcConfig {
        &self.bitcoin
    }

    pub const fn control(&self) -> &ControlServerConfig {
        &self.control
    }
}

pub(crate) enum CandidateConfig {
    Ledger(LedgerRuntimeConfig),
    Holder(HolderRuntimeConfig),
    Committee(CommitteeRuntimeConfig),
}

impl CandidateConfig {
    pub(crate) const fn role(&self) -> RuntimeRole {
        match self {
            Self::Ledger(_) => RuntimeRole::Ledger,
            Self::Holder(_) => RuntimeRole::Holder,
            Self::Committee(_) => RuntimeRole::Committee,
        }
    }

    pub(crate) const fn identity(&self) -> &DeploymentIdentity {
        match self {
            Self::Ledger(value) => &value.identity,
            Self::Holder(value) => &value.identity,
            Self::Committee(value) => &value.identity,
        }
    }

    pub(crate) const fn paths(&self) -> &RuntimePaths {
        match self {
            Self::Ledger(value) => &value.paths,
            Self::Holder(value) => &value.paths,
            Self::Committee(value) => &value.paths,
        }
    }

    pub(crate) const fn committee_member_id(&self) -> Option<CommitteeMemberId> {
        match self {
            Self::Committee(value) => Some(value.member_id),
            Self::Ledger(_) | Self::Holder(_) => None,
        }
    }

    pub(crate) const fn trust_coordinator_identity(
        &self,
    ) -> Option<thunderbolt_cometbft_client::TrustCoordinatorIdentity> {
        match self {
            Self::Holder(value) => Some(value.comet.coordinator.identity()),
            Self::Committee(value) => Some(value.comet.coordinator.identity()),
            Self::Ledger(_) => None,
        }
    }

    pub(crate) fn install_filesystem_audit(&mut self, audit: Arc<crate::validate::FilesystemAudit>) {
        match self {
            Self::Ledger(value) => value.filesystem_audit = Some(audit),
            Self::Holder(value) => value.filesystem_audit = Some(audit),
            Self::Committee(value) => value.filesystem_audit = Some(audit),
        }
    }
}

/// Structurally and semantically parsed policy whose live filesystem
/// references have not yet been audited.
pub struct ParsedRuntimeConfig {
    pub(crate) candidate: CandidateConfig,
}

#[allow(missing_docs)]
impl ParsedRuntimeConfig {
    /// Returns the exact configured role.
    pub const fn role(&self) -> RuntimeRole {
        self.candidate.role()
    }

    pub const fn identity(&self) -> &DeploymentIdentity {
        self.candidate.identity()
    }
}

/// Policy bundle retaining its audited file descriptors and receipts.
///
/// Role policies are exposed only through a fresh [`RuntimeHandoff`]. This is
/// not a production daemon constructor: unavailable cryptographic and external
/// checkpoint capabilities must still be injected separately.
pub struct EffectiveRuntimeConfig {
    pub(crate) candidate: CandidateConfig,
}

#[allow(missing_docs)]
impl EffectiveRuntimeConfig {
    /// Returns the exact configured role.
    pub const fn role(&self) -> RuntimeRole {
        self.candidate.role()
    }

    pub const fn identity(&self) -> &DeploymentIdentity {
        self.candidate.identity()
    }

    pub const fn capabilities(&self) -> CapabilityBoundary {
        match &self.candidate {
            CandidateConfig::Ledger(value) => value.capabilities,
            CandidateConfig::Holder(value) => value.capabilities,
            CandidateConfig::Committee(value) => value.capabilities,
        }
    }

    pub fn redacted(&self) -> RedactedEffectiveConfig {
        RedactedEffectiveConfig::from_effective(self)
    }

    pub(crate) const fn paths(&self) -> &RuntimePaths {
        self.candidate.paths()
    }

    pub(crate) fn filesystem_audit(&self) -> Result<&crate::validate::FilesystemAudit> {
        match &self.candidate {
            CandidateConfig::Ledger(value) => value.filesystem_audit.as_deref(),
            CandidateConfig::Holder(value) => value.filesystem_audit.as_deref(),
            CandidateConfig::Committee(value) => value.filesystem_audit.as_deref(),
        }
        .ok_or(ConfigError::UnsafePath("filesystem audit capability is missing"))
    }

    /// Rechecks inode, ancestry, absence and digest receipts immediately before
    /// constructing downstream services, then returns a borrowed handoff.
    pub fn revalidate_for_handoff(&self) -> Result<RuntimeHandoff<'_>> {
        crate::validate::revalidate_effective(self)?;
        Ok(RuntimeHandoff { config: self })
    }
}

impl fmt::Debug for EffectiveRuntimeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.redacted().fmt(formatter)
    }
}

/// Short-lived, revalidated constructor handoff. Holding this value keeps the
/// original audited file descriptors alive through downstream construction.
pub struct RuntimeHandoff<'a> {
    config: &'a EffectiveRuntimeConfig,
}

impl RuntimeHandoff<'_> {
    /// Returns Ledger policy when this is a Ledger process.
    pub fn ledger(&self) -> Option<&LedgerRuntimeConfig> {
        match &self.config.candidate {
            CandidateConfig::Ledger(value) => Some(value),
            CandidateConfig::Holder(_) | CandidateConfig::Committee(_) => None,
        }
    }

    /// Returns Holder policy when this is a Holder process.
    pub fn holder(&self) -> Option<&HolderRuntimeConfig> {
        match &self.config.candidate {
            CandidateConfig::Holder(value) => Some(value),
            CandidateConfig::Ledger(_) | CandidateConfig::Committee(_) => None,
        }
    }

    /// Returns Committee policy when this is a Committee process.
    pub fn committee(&self) -> Option<&CommitteeRuntimeConfig> {
        match &self.config.candidate {
            CandidateConfig::Committee(value) => Some(value),
            CandidateConfig::Ledger(_) | CandidateConfig::Holder(_) => None,
        }
    }

    /// Constructs the exact committed Comet transport for a Holder or
    /// Committee handoff. Regtest alone may use literal-loopback HTTP.
    pub fn comet_transport(&self) -> Result<CometBftRpcTransport> {
        let (identity, paths, policy) = match &self.config.candidate {
            CandidateConfig::Holder(value) => (&value.identity, &value.paths, &value.comet),
            CandidateConfig::Committee(value) => (&value.identity, &value.paths, &value.comet),
            CandidateConfig::Ledger(_) => {
                return Err(ConfigError::Invalid("Ledger role has no Comet transport"));
            }
        };
        let peer_policies = std::iter::once(policy.primary()).chain(policy.witnesses());
        let peers = if let Some(tls) = paths.comet_tls() {
            let loaded = tls.load_for_handoff()?;
            peer_policies
                .map(|peer| {
                    HttpsPeer::new(
                        peer.endpoint().as_str(),
                        peer.identity().node_id(),
                        *peer.identity().transport_binding(),
                        loaded.ca_certificates().to_vec(),
                        loaded.client_identity(),
                    )
                    .map(RpcPeer::Https)
                    .map_err(|_| ConfigError::PolicyRejected)
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            if identity.network != Network::Regtest {
                return Err(ConfigError::Invalid("plaintext Comet transport is regtest-only"));
            }
            peer_policies
                .map(|peer| {
                    LoopbackHttpPeer::new_regtest(
                        peer.endpoint().as_str(),
                        peer.identity().node_id(),
                        *peer.identity().transport_binding(),
                    )
                    .map(RpcPeer::RegtestLoopback)
                    .map_err(|_| ConfigError::PolicyRejected)
                })
                .collect::<Result<Vec<_>>>()?
        };
        let config = RpcTransportConfig::new(peers, policy.rpc_limits(), policy.rpc_retry())
            .map_err(|_| ConfigError::PolicyRejected)?;
        CometBftRpcTransport::new(config).map_err(|_| ConfigError::PolicyRejected)
    }
}

/// Serializable effective view with every local path and endpoint redacted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RedactedEffectiveConfig {
    /// Configuration schema version.
    pub config_version: u16,
    /// Process role.
    pub role: RuntimeRole,
    /// Canonical network name.
    pub network: &'static str,
    /// Ledger chain identifier.
    pub ledger_chain_id: String,
    /// Public raw deployment bytes in lowercase hexadecimal.
    pub deployment_id_hex: String,
    /// Protocol-suite identifier.
    pub protocol_suite_id: String,
    /// Positive Committee epoch.
    pub committee_epoch: u64,
    /// Committee descriptor digest.
    pub committee_descriptor_digest: String,
    /// Anchor-parameter-suite identifier.
    pub anchor_parameter_suite_id: String,
    /// Runtime profile identifier.
    pub runtime_profile_id: String,
    /// Finality verifier profile identifier.
    pub finality_verifier_profile_id: String,
    /// Canonical exact Comet/finality policy digest.
    pub finality_policy_digest: String,
    /// Redacted local-path marker.
    pub local_paths: &'static str,
    /// Redacted network-endpoint marker.
    pub network_endpoints: &'static str,
    /// Holder-signing availability marker.
    pub holder_signing: &'static str,
    /// Committee-signing availability marker.
    pub committee_threshold_signing: &'static str,
    /// Production Paillier-3072 availability marker.
    pub production_paillier_3072: &'static str,
}

impl RedactedEffectiveConfig {
    fn from_effective(config: &EffectiveRuntimeConfig) -> Self {
        let identity = config.identity();
        Self {
            config_version: CONFIG_VERSION_V2,
            role: config.role(),
            network: network_name(identity.network),
            ledger_chain_id: identity.ledger_chain_id.as_str().to_owned(),
            deployment_id_hex: crate::mapping::hex_encode(&identity.deployment_id),
            protocol_suite_id: crate::mapping::hex_encode(identity.protocol_suite_id.as_bytes()),
            committee_epoch: identity.committee_epoch,
            committee_descriptor_digest: crate::mapping::hex_encode(identity.committee_descriptor_digest.as_bytes()),
            anchor_parameter_suite_id: crate::mapping::hex_encode(identity.anchor_parameter_suite_id.as_bytes()),
            runtime_profile_id: crate::mapping::hex_encode(&identity.runtime_profile_id),
            finality_verifier_profile_id: crate::mapping::hex_encode(&identity.finality_verifier_profile_id),
            finality_policy_digest: crate::mapping::hex_encode(&identity.finality_policy_digest),
            local_paths: "<redacted>",
            network_endpoints: "<redacted>",
            holder_signing: "unavailable",
            committee_threshold_signing: "unavailable",
            production_paillier_3072: "unavailable",
        }
    }

    /// Serializes the redacted diagnostic view as TOML.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|_| ConfigError::Invalid("redacted TOML encoding failed"))
    }
}

/// Result of checking one Ledger, one or more Holder, and one or more Committee
/// configurations against the exact same deployment and profile sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeploymentConsistency {
    config_count: usize,
    committee_member_count: usize,
}

#[allow(missing_docs)]
impl DeploymentConsistency {
    /// Returns the number of checked role documents.
    pub const fn config_count(self) -> usize {
        self.config_count
    }

    pub const fn committee_member_count(self) -> usize {
        self.committee_member_count
    }
}

/// Rejects cross-role identity/profile/source drift and writable-path reuse.
pub fn check_deployment_consistency(configs: &[&ParsedRuntimeConfig]) -> Result<DeploymentConsistency> {
    let candidates = configs.iter().map(|config| &config.candidate).collect::<Vec<_>>();
    check_candidate_deployment_consistency(&candidates)
}

fn check_candidate_deployment_consistency(configs: &[&CandidateConfig]) -> Result<DeploymentConsistency> {
    let first = configs.first().ok_or(ConfigError::DeploymentMismatch)?;
    let identity = first.identity();
    let paths = first.paths();
    let mut ledger_count = 0_usize;
    let mut holder_count = 0_usize;
    let mut committee_members = Vec::new();
    let mut prior_process_paths: Vec<&Path> = Vec::new();
    let mut prior_reference_paths: Vec<&Path> = Vec::new();
    let mut exclusive_references: Vec<&Path> = Vec::new();
    let mut trust_coordinator_identities = Vec::new();
    let mut checkpoint_provider_ids = Vec::new();
    let mut checkpoint_trust_domains = Vec::new();
    for config in configs {
        if config.identity() != identity {
            return Err(ConfigError::DeploymentMismatch);
        }
        let current_paths = config.paths();
        if current_paths.committee_descriptor != paths.committee_descriptor
            || current_paths.anchor_suite_registry != paths.anchor_suite_registry
            || current_paths.profile_manifest != paths.profile_manifest
        {
            return Err(ConfigError::DeploymentMismatch);
        }
        let current_process_paths = current_paths.writable_paths();
        let current_reference_paths = current_paths.all_reference_paths();
        for path in &current_process_paths {
            if prior_process_paths.iter().any(|other| paths_overlap(path, other))
                || prior_reference_paths.iter().any(|other| paths_overlap(path, other))
                || current_reference_paths.iter().any(|other| paths_overlap(path, other))
            {
                return Err(ConfigError::DeploymentMismatch);
            }
        }
        for path in &current_reference_paths {
            if prior_process_paths.iter().any(|other| paths_overlap(path, other)) {
                return Err(ConfigError::DeploymentMismatch);
            }
        }
        prior_process_paths.extend(current_process_paths);
        prior_reference_paths.extend(current_reference_paths);
        for path in current_paths.exclusive_reference_paths() {
            if exclusive_references.contains(&path) {
                return Err(ConfigError::DeploymentMismatch);
            }
            exclusive_references.push(path);
        }
        for (provider_id, trust_domain_id) in current_paths.checkpoint_identities() {
            if checkpoint_provider_ids.contains(&provider_id) || checkpoint_trust_domains.contains(&trust_domain_id) {
                return Err(ConfigError::DeploymentMismatch);
            }
            checkpoint_provider_ids.push(provider_id);
            checkpoint_trust_domains.push(trust_domain_id);
        }
        if let Some(coordinator_identity) = config.trust_coordinator_identity() {
            if trust_coordinator_identities.contains(&coordinator_identity) {
                return Err(ConfigError::DeploymentMismatch);
            }
            trust_coordinator_identities.push(coordinator_identity);
        }
        match config.role() {
            RuntimeRole::Ledger => ledger_count = ledger_count.saturating_add(1),
            RuntimeRole::Holder => holder_count = holder_count.saturating_add(1),
            RuntimeRole::Committee => {
                let member = config.committee_member_id().ok_or(ConfigError::DeploymentMismatch)?;
                if committee_members.contains(&member) {
                    return Err(ConfigError::DeploymentMismatch);
                }
                committee_members.push(member);
            }
        }
    }
    if ledger_count != 1 || holder_count == 0 || committee_members.is_empty() {
        return Err(ConfigError::DeploymentMismatch);
    }
    Ok(DeploymentConsistency {
        config_count: configs.len(),
        committee_member_count: committee_members.len(),
    })
}

/// Rechecks cross-role semantics plus live inode identities after every role
/// has completed filesystem validation.
pub fn check_effective_deployment_consistency(configs: &[&EffectiveRuntimeConfig]) -> Result<DeploymentConsistency> {
    for config in configs {
        crate::validate::revalidate_effective(config)?;
    }
    let candidates = configs.iter().map(|config| &config.candidate).collect::<Vec<_>>();
    let deployment = check_candidate_deployment_consistency(&candidates)?;
    let mut file_identities: std::collections::BTreeMap<(u64, u64), bool> = std::collections::BTreeMap::new();
    for config in configs {
        for (file_identity, exclusive) in config.filesystem_audit()?.file_identities() {
            if file_identities
                .insert(file_identity, exclusive)
                .is_some_and(|prior_exclusive| prior_exclusive || exclusive)
            {
                return Err(ConfigError::DeploymentMismatch);
            }
        }
    }
    Ok(deployment)
}

fn paths_overlap(first: &Path, second: &Path) -> bool {
    first == second || first.starts_with(second) || second.starts_with(first)
}

pub(crate) fn network_name(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "mainnet",
        Network::Testnet => "testnet3",
        Network::Testnet4 => "testnet4",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
    }
}

pub(crate) struct ParsedCometPeer {
    pub(crate) endpoint: Url,
    pub(crate) identity: PeerIdentity,
}
