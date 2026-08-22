use core::future::Future;
use core::pin::Pin;
use std::error::Error;

use serde::Serialize;
use thunderbolt_runtime_config::{
    CommitteeRuntimeConfig, DeploymentIdentity, HolderRuntimeConfig, LedgerRuntimeConfig, RuntimeRole,
};
use tokio_util::sync::CancellationToken;

/// Runtime-shell status and control schema version.
pub const RUNTIME_SHELL_VERSION_V2: u16 = 2;

/// Role lifecycle states owned exclusively by the bounded supervisor actor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeLifecycleState {
    /// Resources and process lock are held; the role handler has not started.
    Initialized,
    /// The fixed start hook is in progress.
    Starting,
    /// The handler started successfully.
    Running,
    /// New role work is disabled and the drain hook completed.
    Draining,
    /// The fixed stop hook is in progress.
    Stopping,
    /// The stop hook and durable clean-marker transition completed.
    Stopped,
    /// A supervised failure terminated the actor.
    Faulted,
}

/// Process/actor liveness, separate from protocol readiness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeLiveness {
    /// The lifecycle actor is actively being polled.
    Live,
    /// The lifecycle actor is not running.
    NotLive,
}

/// Protocol readiness, which is never inferred from process liveness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeReadiness {
    /// Reserved for a future reviewed capability-attestation transition.
    /// This stepping-stone crate never emits it.
    Ready,
    /// At least one immutable blocker, lifecycle gate, or fault remains.
    NotReady,
}

/// Stable redacted terminal fault codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeFaultCode {
    /// A role lifecycle hook returned an error.
    HandlerFailure,
    /// A role lifecycle hook exceeded its committed deadline.
    HandlerDeadline,
    /// A role lifecycle hook panicked.
    HandlerPanic,
    /// Every runtime handle disappeared while the actor was live.
    ActorChannelClosed,
    /// The actor future was dropped without a terminal transition.
    ActorCancelled,
    /// A durable dirty/clean marker update failed.
    ProcessStateUnavailable,
}

/// Readiness-blocker classification for operator tooling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeBlockerCategory {
    /// A required production capability is not implemented or injected.
    Capability,
    /// The committed runtime profile is intentionally non-production.
    Profile,
    /// A prior unclean process lifetime requires external recovery.
    Recovery,
}

/// Stable structured blocker codes. A runtime instance cannot remove or add codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeBlockerCode {
    /// The committed configuration explicitly selects a non-production deployment.
    NonProductionProfile,
    /// No production static admission verifier is wired into the Ledger.
    StaticAdmissionVerifierUnavailable,
    /// No reviewed bounded production ABCI dispatcher is wired into the Ledger.
    BoundedAbciDispatcherUnavailable,
    /// The reviewed Holder signing capability is unavailable.
    HolderSigningUnavailable,
    /// The Holder settlement/Bitcoin broadcast bridge is unavailable.
    HolderSettlementUnavailable,
    /// The Committee threshold signing capability is unavailable.
    CommitteeThresholdSigningUnavailable,
    /// Reviewed Committee DKG and member provisioning are unavailable.
    CommitteeDkgProvisioningUnavailable,
    /// No production external consensus-finality verifier is injected.
    ExternalFinalityVerifierUnavailable,
    /// No concrete authenticated Comet transport is wired into the role runtime.
    AuthenticatedCometTransportUnavailable,
    /// No independently authenticated rollback-floor provider is injected.
    RollbackFloorProviderUnavailable,
    /// The production Paillier-3072 execution capability is unavailable.
    ProductionPaillier3072Unavailable,
    /// The prior process lifetime did not complete a durable clean stop.
    DirtyRestartRecoveryRequired,
}

impl RuntimeBlockerCode {
    /// Returns the stable machine-readable code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NonProductionProfile => "non_production_profile",
            Self::StaticAdmissionVerifierUnavailable => "static_admission_verifier_unavailable",
            Self::BoundedAbciDispatcherUnavailable => "bounded_abci_dispatcher_unavailable",
            Self::HolderSigningUnavailable => "holder_signing_unavailable",
            Self::HolderSettlementUnavailable => "holder_settlement_unavailable",
            Self::CommitteeThresholdSigningUnavailable => "committee_threshold_signing_unavailable",
            Self::CommitteeDkgProvisioningUnavailable => "committee_dkg_provisioning_unavailable",
            Self::ExternalFinalityVerifierUnavailable => "external_finality_verifier_unavailable",
            Self::AuthenticatedCometTransportUnavailable => "authenticated_comet_transport_unavailable",
            Self::RollbackFloorProviderUnavailable => "rollback_floor_provider_unavailable",
            Self::ProductionPaillier3072Unavailable => "production_paillier_3072_unavailable",
            Self::DirtyRestartRecoveryRequired => "dirty_restart_recovery_required",
        }
    }
}

/// One immutable machine-readable readiness blocker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct RuntimeBlocker {
    category: RuntimeBlockerCategory,
    code: RuntimeBlockerCode,
}

impl RuntimeBlocker {
    pub(crate) const fn capability(code: RuntimeBlockerCode) -> Self {
        Self {
            category: RuntimeBlockerCategory::Capability,
            code,
        }
    }

    pub(crate) const fn profile(code: RuntimeBlockerCode) -> Self {
        Self {
            category: RuntimeBlockerCategory::Profile,
            code,
        }
    }

    pub(crate) const fn recovery(code: RuntimeBlockerCode) -> Self {
        Self {
            category: RuntimeBlockerCategory::Recovery,
            code,
        }
    }

    /// Returns the blocker class.
    pub const fn category(self) -> RuntimeBlockerCategory {
        self.category
    }

    /// Returns the stable blocker code.
    pub const fn code(self) -> RuntimeBlockerCode {
        self.code
    }
}

/// Secret-free runtime status snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct RuntimeStatus {
    runtime_version: u16,
    role: RuntimeRole,
    lifecycle: RuntimeLifecycleState,
    liveness: RuntimeLiveness,
    readiness: RuntimeReadiness,
    fault: Option<RuntimeFaultCode>,
}

impl RuntimeStatus {
    pub(crate) const fn new(
        role: RuntimeRole,
        lifecycle: RuntimeLifecycleState,
        liveness: RuntimeLiveness,
        readiness: RuntimeReadiness,
        fault: Option<RuntimeFaultCode>,
    ) -> Self {
        Self {
            runtime_version: RUNTIME_SHELL_VERSION_V2,
            role,
            lifecycle,
            liveness,
            readiness,
            fault,
        }
    }

    /// Returns the runtime-shell schema version.
    pub const fn runtime_version(self) -> u16 {
        self.runtime_version
    }

    /// Returns the immutable process role.
    pub const fn role(self) -> RuntimeRole {
        self.role
    }

    /// Returns the serialized lifecycle state.
    pub const fn lifecycle(self) -> RuntimeLifecycleState {
        self.lifecycle
    }

    /// Returns whether the bounded lifecycle actor is live.
    pub const fn liveness(self) -> RuntimeLiveness {
        self.liveness
    }

    /// Returns protocol readiness independently of liveness. This crate version
    /// always returns [`RuntimeReadiness::NotReady`].
    pub const fn readiness(self) -> RuntimeReadiness {
        self.readiness
    }

    /// Returns a stable terminal fault code, if any.
    pub const fn fault(self) -> Option<RuntimeFaultCode> {
        self.fault
    }
}

/// Public identity-only configuration view retained from a revalidated handoff.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RedactedRuntimeConfig {
    runtime_version: u16,
    role: RuntimeRole,
    network: String,
    ledger_chain_id: String,
    deployment_id_hex: String,
    protocol_suite_id: String,
    committee_epoch: u64,
    committee_descriptor_digest: String,
    anchor_parameter_suite_id: String,
    runtime_profile_id: String,
    finality_verifier_profile_id: String,
    finality_policy_digest: String,
    local_paths: &'static str,
    network_endpoints: &'static str,
    secret_material: &'static str,
}

impl RedactedRuntimeConfig {
    pub(crate) fn from_identity(role: RuntimeRole, identity: &DeploymentIdentity) -> Self {
        Self {
            runtime_version: RUNTIME_SHELL_VERSION_V2,
            role,
            network: identity.network().to_string(),
            ledger_chain_id: identity.ledger_chain_id().as_str().to_owned(),
            deployment_id_hex: hex::encode(identity.deployment_id()),
            protocol_suite_id: hex::encode(identity.protocol_suite_id().as_bytes()),
            committee_epoch: identity.committee_epoch(),
            committee_descriptor_digest: hex::encode(identity.committee_descriptor_digest().as_bytes()),
            anchor_parameter_suite_id: hex::encode(identity.anchor_parameter_suite_id().as_bytes()),
            runtime_profile_id: hex::encode(identity.runtime_profile_id()),
            finality_verifier_profile_id: hex::encode(identity.finality_verifier_profile_id()),
            finality_policy_digest: hex::encode(identity.finality_policy_digest()),
            local_paths: "<redacted>",
            network_endpoints: "<redacted>",
            secret_material: "<never-loaded>",
        }
    }

    /// Returns the exact role.
    pub const fn role(&self) -> RuntimeRole {
        self.role
    }

    /// Returns the immutable runtime-profile identifier.
    pub fn runtime_profile_id(&self) -> &str {
        &self.runtime_profile_id
    }

    /// Encodes the bounded secret-free view as canonical compact JSON.
    pub fn to_json(&self) -> crate::Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| crate::RuntimeError::DiagnosticEncoding)
    }
}

/// Fixed role lifecycle operations. No raw protocol mutation is exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeLifecycleEvent {
    /// Start the role-owned service boundary.
    Start,
    /// Stop accepting new role work and drain admitted work.
    Drain,
    /// Stop the role-owned service boundary.
    Stop,
}

mod sealed {
    pub trait Sealed {}
}

/// Sealed marker implemented only by the three supported process roles.
pub trait RuntimeRoleMarker: sealed::Sealed + Send + Sync + 'static {
    /// Exact configuration role accepted by this marker.
    const ROLE: RuntimeRole;
}

/// Ledger-process marker.
pub enum LedgerRole {}

/// Holder-process marker.
pub enum HolderRole {}

/// Committee-process marker.
pub enum CommitteeRole {}

impl sealed::Sealed for LedgerRole {}
impl sealed::Sealed for HolderRole {}
impl sealed::Sealed for CommitteeRole {}

impl RuntimeRoleMarker for LedgerRole {
    const ROLE: RuntimeRole = RuntimeRole::Ledger;
}

impl RuntimeRoleMarker for HolderRole {
    const ROLE: RuntimeRole = RuntimeRole::Holder;
}

impl RuntimeRoleMarker for CommitteeRole {
    const ROLE: RuntimeRole = RuntimeRole::Committee;
}

/// Exact public deployment and profile identity implemented by a role handler.
///
/// Construction accepts only a validated runtime-config identity, preventing a
/// caller from assembling a partial or stringly typed binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeHandlerIdentity {
    pub(crate) role: RuntimeRole,
    pub(crate) network: String,
    pub(crate) ledger_chain_id_hex: String,
    pub(crate) deployment_id_hex: String,
    pub(crate) protocol_suite_id: String,
    pub(crate) bitcoin_genesis_hash: String,
    pub(crate) committee_epoch: u64,
    pub(crate) committee_descriptor_digest: String,
    pub(crate) anchor_parameter_suite_id: String,
    pub(crate) runtime_profile_id: [u8; 32],
    pub(crate) finality_verifier_profile_id: [u8; 32],
    pub(crate) finality_policy_digest: [u8; 32],
    pub(crate) role_binding: String,
}

impl RuntimeHandlerIdentity {
    /// Derives the complete Ledger binding, including admission and consensus profiles.
    pub fn for_ledger(config: &LedgerRuntimeConfig) -> Self {
        Self::from_deployment(
            RuntimeRole::Ledger,
            config.identity(),
            format!(
                "consensus={};static_verifier={};deployment_descriptor={}",
                hex::encode(config.consensus_profile().as_bytes()),
                hex::encode(config.static_verifier_profile_id()),
                hex::encode(config.deployment_descriptor_digest()),
            ),
        )
    }

    /// Derives the complete Holder binding from validated role configuration.
    pub fn for_holder(config: &HolderRuntimeConfig) -> Self {
        Self::from_deployment(RuntimeRole::Holder, config.identity(), "holder".to_owned())
    }

    /// Derives the complete Committee binding, including the exact member ID.
    pub fn for_committee(config: &CommitteeRuntimeConfig) -> Self {
        Self::from_deployment(
            RuntimeRole::Committee,
            config.identity(),
            format!("committee_member={}", config.member_id().get()),
        )
    }

    fn from_deployment(role: RuntimeRole, identity: &DeploymentIdentity, role_binding: String) -> Self {
        Self {
            role,
            network: identity.network().to_string(),
            ledger_chain_id_hex: hex::encode(identity.ledger_chain_id().as_bytes()),
            deployment_id_hex: hex::encode(identity.deployment_id()),
            protocol_suite_id: hex::encode(identity.protocol_suite_id().as_bytes()),
            bitcoin_genesis_hash: hex::encode(identity.bitcoin_genesis_hash().as_bytes()),
            committee_epoch: identity.committee_epoch(),
            committee_descriptor_digest: hex::encode(identity.committee_descriptor_digest().as_bytes()),
            anchor_parameter_suite_id: hex::encode(identity.anchor_parameter_suite_id().as_bytes()),
            runtime_profile_id: *identity.runtime_profile_id(),
            finality_verifier_profile_id: *identity.finality_verifier_profile_id(),
            finality_policy_digest: *identity.finality_policy_digest(),
            role_binding,
        }
    }

    /// Returns the exact role encoded into the binding.
    pub const fn role(&self) -> RuntimeRole {
        self.role
    }

    /// Returns the exact runtime-manifest profile.
    pub const fn runtime_profile_id(&self) -> &[u8; 32] {
        &self.runtime_profile_id
    }

    /// Returns the exact finality-verifier policy profile.
    pub const fn finality_verifier_profile_id(&self) -> &[u8; 32] {
        &self.finality_verifier_profile_id
    }
}

/// Boxed cancellation-safe lifecycle-hook future.
pub type RuntimeHandlerFuture<'a, E> = Pin<Box<dyn Future<Output = std::result::Result<(), E>> + Send + 'a>>;

/// Mandatory role-typed and profile-bound lifecycle handler.
///
/// Implementations must be cancellation-safe: dropping the future or observing
/// the supplied cancellation token must leave no half-applied lifecycle
/// mutation. `on_lifecycle` itself must only construct the future; lifecycle
/// side effects begin when that future is polled. Blocking work belongs on a
/// separately bounded executor. The runtime never exports a default, demo, or
/// accept-all handler.
pub trait RuntimeLifecycleHandler<R: RuntimeRoleMarker>: Send + Sync + 'static {
    /// Potentially sensitive handler error. The supervisor never serializes it.
    type Error: Error + Send + Sync + 'static;

    /// Returns the exact deployment and profiles implemented by this handler.
    fn identity(&self) -> RuntimeHandlerIdentity;

    /// Applies one fixed lifecycle event under a supervisor-owned cancellation token.
    fn on_lifecycle(
        &self,
        event: RuntimeLifecycleEvent,
        cancellation: CancellationToken,
    ) -> RuntimeHandlerFuture<'_, Self::Error>;
}

pub(crate) const COMMON_BLOCKERS: &[RuntimeBlocker] =
    &[RuntimeBlocker::profile(RuntimeBlockerCode::NonProductionProfile)];

pub(crate) const LEDGER_BLOCKERS: &[RuntimeBlocker] = &[
    RuntimeBlocker::capability(RuntimeBlockerCode::StaticAdmissionVerifierUnavailable),
    RuntimeBlocker::capability(RuntimeBlockerCode::BoundedAbciDispatcherUnavailable),
];

pub(crate) const HOLDER_BLOCKERS: &[RuntimeBlocker] = &[
    RuntimeBlocker::capability(RuntimeBlockerCode::HolderSigningUnavailable),
    RuntimeBlocker::capability(RuntimeBlockerCode::HolderSettlementUnavailable),
    RuntimeBlocker::capability(RuntimeBlockerCode::ExternalFinalityVerifierUnavailable),
    RuntimeBlocker::capability(RuntimeBlockerCode::AuthenticatedCometTransportUnavailable),
    RuntimeBlocker::capability(RuntimeBlockerCode::RollbackFloorProviderUnavailable),
    RuntimeBlocker::capability(RuntimeBlockerCode::ProductionPaillier3072Unavailable),
];

pub(crate) const COMMITTEE_BLOCKERS: &[RuntimeBlocker] = &[
    RuntimeBlocker::capability(RuntimeBlockerCode::CommitteeThresholdSigningUnavailable),
    RuntimeBlocker::capability(RuntimeBlockerCode::CommitteeDkgProvisioningUnavailable),
    RuntimeBlocker::capability(RuntimeBlockerCode::ExternalFinalityVerifierUnavailable),
    RuntimeBlocker::capability(RuntimeBlockerCode::AuthenticatedCometTransportUnavailable),
    RuntimeBlocker::capability(RuntimeBlockerCode::RollbackFloorProviderUnavailable),
    RuntimeBlocker::capability(RuntimeBlockerCode::ProductionPaillier3072Unavailable),
];
