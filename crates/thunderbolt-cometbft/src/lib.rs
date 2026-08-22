//! CometBFT light-client finality verification for Bitcoin Thunderbolt.
//!
//! CometBFT places the application hash returned while executing height `H`
//! into the signed header at height `H + 1`. This crate checks that one-block
//! delay explicitly and returns an opaque capability only after verifying an
//! adjacent light-client trace from an operator-pinned trust root.

#![deny(missing_docs)]
#![deny(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]
#![forbid(unsafe_code)]

use core::time::Duration;
use std::collections::BTreeSet;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{SystemTime, UNIX_EPOCH};

use tendermint::block::Header;
use tendermint::hash::Hash;
use tendermint::trust_threshold::TrustThresholdFraction;
use tendermint::Time;
use tendermint_light_client_verifier::options::Options;
use tendermint_light_client_verifier::types::LightBlock;
use tendermint_light_client_verifier::{ProdVerifier, Verdict, Verifier as _};
use thiserror::Error;
use thunderbolt_ledger::{AppHashV2, ExecutedBlockV2, LedgerChainIdV2};

/// Maximum validators accepted in one CometBFT light block.
pub const MAX_VALIDATORS: usize = 64;
/// Maximum adjacent headers accepted in one trust update.
pub const MAX_ADJACENT_HEADERS: usize = 2_048;
/// Minimum supported trusting period.
pub const MIN_TRUSTING_PERIOD: Duration = Duration::from_secs(60);
/// Maximum supported trusting period. The actual value must remain below the
/// validator-set unbonding period chosen by the deployment.
pub const MAX_TRUSTING_PERIOD: Duration = Duration::from_secs(365 * 24 * 60 * 60);
/// Maximum accepted local clock-drift allowance.
pub const MAX_CLOCK_DRIFT: Duration = Duration::from_secs(60);
/// ABCI application-version value reserved for the Thunderbolt v2 runtime.
pub const THUNDERBOLT_APP_VERSION_V2: u64 = 2;
/// Maximum independent witnesses accepted for one update.
pub const MAX_WITNESSES: usize = 4;
/// Maximum Ed25519 commit signatures verified in one call, across the primary
/// and every witness trace.
pub const MAX_SIGNATURE_CHECKS_PER_CALL: usize = 16_384;
/// Maximum aggregate validator-name bytes accepted in one light block.
pub const MAX_VALIDATOR_NAME_BYTES: usize = 4 * 1024;

/// Errors returned before a value can become a finality capability.
#[derive(Debug, Error)]
pub enum FinalityError {
    /// The configured verifier policy is outside the supported safety bounds.
    #[error("invalid finality policy: {0}")]
    InvalidPolicy(&'static str),
    /// The operator-pinned trust root does not match the supplied light block.
    #[error("invalid pinned trust root: {0}")]
    InvalidTrustRoot(&'static str),
    /// The supplied light block or adjacent trace is malformed or outside bounds.
    #[error("invalid light-client trace: {0}")]
    InvalidTrace(&'static str),
    /// CometBFT signature, validator-set, time, or trust verification failed.
    #[error("CometBFT light-client verification failed")]
    LightClientVerification,
    /// The independently sourced witness traces were missing or conflicted.
    #[error("CometBFT witness verification failed: {0}")]
    WitnessVerification(&'static str),
    /// The deterministic execution output does not match the verified headers.
    #[error("executed application state does not match the verified CometBFT headers: {0}")]
    ExecutionBinding(&'static str),
    /// A Tendermint header hash could not be computed without unwinding.
    #[error("CometBFT header hashing failed")]
    HeaderHash,
    /// The trusted local wall clock was unavailable or outside CometBFT's range.
    #[error("trusted local clock is unavailable")]
    Clock,
}

/// Immutable light-client verification policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalityPolicy {
    trusting_period: Duration,
    clock_drift: Duration,
    max_validators: usize,
    max_adjacent_headers: usize,
    min_witnesses: usize,
    max_witnesses: usize,
}

impl FinalityPolicy {
    /// Constructs a bounded production policy.
    pub fn new(
        trusting_period: Duration,
        clock_drift: Duration,
        max_validators: usize,
        max_adjacent_headers: usize,
        min_witnesses: usize,
        max_witnesses: usize,
    ) -> Result<Self, FinalityError> {
        if !(MIN_TRUSTING_PERIOD..=MAX_TRUSTING_PERIOD).contains(&trusting_period) {
            return Err(FinalityError::InvalidPolicy(
                "trusting period is outside the supported bound",
            ));
        }
        if clock_drift > MAX_CLOCK_DRIFT {
            return Err(FinalityError::InvalidPolicy("clock drift exceeds the supported bound"));
        }
        if max_validators == 0 || max_validators > MAX_VALIDATORS {
            return Err(FinalityError::InvalidPolicy(
                "validator count is outside the supported bound",
            ));
        }
        if !(2..=MAX_ADJACENT_HEADERS).contains(&max_adjacent_headers) {
            return Err(FinalityError::InvalidPolicy(
                "adjacent-header count is outside the supported bound",
            ));
        }
        if min_witnesses == 0 || min_witnesses > max_witnesses || max_witnesses > MAX_WITNESSES {
            return Err(FinalityError::InvalidPolicy(
                "witness count is outside the supported bound",
            ));
        }
        let signature_budget = max_validators
            .checked_mul(max_adjacent_headers)
            .and_then(|count| count.checked_mul(max_witnesses + 1))
            .ok_or(FinalityError::InvalidPolicy("signature work budget overflows"))?;
        if signature_budget > MAX_SIGNATURE_CHECKS_PER_CALL {
            return Err(FinalityError::InvalidPolicy(
                "configured validator, trace, and witness bounds exceed the signature work budget",
            ));
        }
        Ok(Self {
            trusting_period,
            clock_drift,
            max_validators,
            max_adjacent_headers,
            min_witnesses,
            max_witnesses,
        })
    }

    /// Returns the configured trusting period.
    pub const fn trusting_period(&self) -> Duration {
        self.trusting_period
    }

    /// Returns the configured maximum local clock drift.
    pub const fn clock_drift(&self) -> Duration {
        self.clock_drift
    }

    /// Returns the configured validator-set bound.
    pub const fn max_validators(&self) -> usize {
        self.max_validators
    }

    /// Returns the maximum adjacent headers accepted per update.
    pub const fn max_adjacent_headers(&self) -> usize {
        self.max_adjacent_headers
    }

    /// Returns the minimum independent witness count required for finality.
    pub const fn min_witnesses(&self) -> usize {
        self.min_witnesses
    }

    /// Returns the maximum witness count accepted in one call.
    pub const fn max_witnesses(&self) -> usize {
        self.max_witnesses
    }

    fn verifier_options(&self) -> Options {
        Options {
            trust_threshold: TrustThresholdFraction::ONE_THIRD,
            trusting_period: self.trusting_period,
            clock_drift: self.clock_drift,
        }
    }
}

impl Default for FinalityPolicy {
    fn default() -> Self {
        Self {
            trusting_period: Duration::from_secs(14 * 24 * 60 * 60),
            clock_drift: Duration::from_secs(10),
            max_validators: 16,
            max_adjacent_headers: 256,
            min_witnesses: 1,
            max_witnesses: 3,
        }
    }
}

/// Operator-pinned CometBFT light-client trust root.
///
/// Construction requires an independently obtained exact height and header
/// hash. The constructor validates all supplied validator data and the commit,
/// but it cannot establish the out-of-band trustworthiness of those pins.
#[derive(Clone, Debug)]
pub struct PinnedTrustRoot {
    block: LightBlock,
    header_hash: [u8; 32],
    ledger_chain_id: LedgerChainIdV2,
    application_version: u64,
    policy: FinalityPolicy,
}

impl PinnedTrustRoot {
    /// Validates a light block against an independently pinned chain, height,
    /// and SHA-256 header hash.
    pub fn new(
        block: LightBlock,
        expected_chain_id: &LedgerChainIdV2,
        expected_height: u64,
        expected_header_hash: [u8; 32],
        policy: FinalityPolicy,
    ) -> Result<Self, FinalityError> {
        validate_light_block_shape(&block, expected_chain_id, policy.max_validators)?;
        if block.signed_header.header.version.app != THUNDERBOLT_APP_VERSION_V2 {
            return Err(FinalityError::InvalidTrustRoot(
                "ABCI application version does not match the operator pin",
            ));
        }
        if height_u64(&block)? != expected_height {
            return Err(FinalityError::InvalidTrustRoot(
                "height does not match the operator pin",
            ));
        }
        let actual = sha256_header_hash(&block.signed_header.header)?;
        if actual != expected_header_hash {
            return Err(FinalityError::InvalidTrustRoot(
                "header hash does not match the operator pin",
            ));
        }
        let verifier = ProdVerifier::default();
        let verdicts = catch_unwind(AssertUnwindSafe(|| {
            (
                verifier.verify_validator_sets(&block.as_untrusted_state()),
                verifier.verify_commit(&block.as_untrusted_state()),
            )
        }))
        .map_err(|_| FinalityError::InvalidTrustRoot("light-client verifier unwound"))?;
        if !matches!(verdicts.0, Verdict::Success) || !matches!(verdicts.1, Verdict::Success) {
            return Err(FinalityError::InvalidTrustRoot(
                "validator sets or commit do not validate against the pinned header",
            ));
        }
        Ok(Self {
            block,
            header_hash: actual,
            ledger_chain_id: expected_chain_id.clone(),
            application_version: THUNDERBOLT_APP_VERSION_V2,
            policy,
        })
    }

    /// Returns the trusted CometBFT height.
    pub fn height(&self) -> u64 {
        self.block.signed_header.header.height.value()
    }

    /// Returns the exact pinned header hash.
    pub const fn header_hash(&self) -> &[u8; 32] {
        &self.header_hash
    }

    /// Borrows the validated light block for durable trusted-state storage.
    pub const fn light_block(&self) -> &LightBlock {
        &self.block
    }

    /// Returns the chain id bound into this trust root.
    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    /// Returns the ABCI application version bound into this trust root.
    pub const fn application_version(&self) -> u64 {
        self.application_version
    }

    /// Returns the exact verifier policy bound into this trust root.
    pub const fn policy(&self) -> FinalityPolicy {
        self.policy
    }

    fn from_verified(
        block: LightBlock,
        header_hash: [u8; 32],
        ledger_chain_id: LedgerChainIdV2,
        application_version: u64,
        policy: FinalityPolicy,
    ) -> Self {
        Self {
            block,
            header_hash,
            ledger_chain_id,
            application_version,
            policy,
        }
    }
}

/// Role of an independently authenticated CometBFT RPC trace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceRole {
    /// Primary RPC provider used to obtain the candidate update.
    Primary,
    /// Independent witness RPC provider at the given zero-based position.
    Witness(u8),
}

/// Exact trace metadata presented to a trusted source authenticator.
#[derive(Clone, Debug)]
pub struct TraceAuthenticationRequest<'a> {
    role: TraceRole,
    ledger_chain_id: LedgerChainIdV2,
    first_height: u64,
    last_height: u64,
    blocks: &'a [LightBlock],
}

impl<'a> TraceAuthenticationRequest<'a> {
    /// Returns whether this source is the primary or a witness.
    pub const fn role(&self) -> TraceRole {
        self.role
    }

    /// Returns the exact expected Ledger chain id.
    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    /// Returns the first adjacent height requested from this source.
    pub const fn first_height(&self) -> u64 {
        self.first_height
    }

    /// Returns the final committing height requested from this source.
    pub const fn last_height(&self) -> u64 {
        self.last_height
    }

    /// Borrows the untrusted blocks received through the source session.
    pub const fn blocks(&self) -> &'a [LightBlock] {
        self.blocks
    }
}

/// One-use authority allowing a trusted transport to bind its authenticated
/// peer identity to exactly the trace under verification.
pub struct TraceAuthenticationCapability<'a> {
    role: TraceRole,
    blocks: &'a [LightBlock],
}

impl<'a> TraceAuthenticationCapability<'a> {
    /// Binds an identity proven by the transport session to this exact trace.
    ///
    /// Callers must invoke this only after authenticating the endpoint against
    /// immutable local peer configuration, such as a pinned mTLS SPKI.
    pub fn bind(self, authenticated_peer_id: tendermint::node::Id) -> AuthenticatedTrace<'a> {
        AuthenticatedTrace {
            role: self.role,
            blocks: self.blocks,
            peer_id: authenticated_peer_id,
        }
    }
}

/// Opaque trace whose source identity was approved by a trusted authenticator.
pub struct AuthenticatedTrace<'a> {
    role: TraceRole,
    blocks: &'a [LightBlock],
    peer_id: tendermint::node::Id,
}

/// Trusted local boundary that authenticates primary and witness RPC sources.
///
/// Implementations must bind the actual authenticated transport session to the
/// exact request. They must never use `LightBlock.provider` or request-supplied
/// labels as authentication. This crate provides no permissive implementation.
pub trait TraceSourceAuthenticator: Send + Sync {
    /// Implementation-specific authentication failure.
    type Error;

    /// Authenticates the source and consumes the one-use binding capability.
    fn authenticate<'a>(
        &self,
        request: TraceAuthenticationRequest<'a>,
        capability: TraceAuthenticationCapability<'a>,
    ) -> Result<AuthenticatedTrace<'a>, Self::Error>;
}

/// Finality capability for one deterministically executed Thunderbolt block.
///
/// This type is intentionally neither serializable nor deserializable.
/// Cross-process consumers must verify the complete proof locally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CometBftFinalityReceipt {
    ledger_chain_id: LedgerChainIdV2,
    application_version: u64,
    execution_height: u64,
    execution_block_time_ms: u64,
    application_hash: AppHashV2,
    execution_header_hash: [u8; 32],
    committing_height: u64,
    committing_header_hash: [u8; 32],
    primary_peer_id: tendermint::node::Id,
    witness_peer_ids: Vec<tendermint::node::Id>,
}

impl CometBftFinalityReceipt {
    /// Returns the verified Ledger chain id.
    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    /// Returns the exact ABCI application version from the verified headers.
    pub const fn application_version(&self) -> u64 {
        self.application_version
    }

    /// Returns the executed Thunderbolt block height.
    pub const fn execution_height(&self) -> u64 {
        self.execution_height
    }

    /// Returns the CometBFT header time used during deterministic execution.
    pub const fn execution_block_time_ms(&self) -> u64 {
        self.execution_block_time_ms
    }

    /// Returns the finality-bound Thunderbolt application hash.
    pub const fn application_hash(&self) -> &AppHashV2 {
        &self.application_hash
    }

    /// Returns the hash of the signed header at the execution height.
    pub const fn execution_header_hash(&self) -> &[u8; 32] {
        &self.execution_header_hash
    }

    /// Returns the next height whose signed header commits the application hash.
    pub const fn committing_height(&self) -> u64 {
        self.committing_height
    }

    /// Returns the hash of the signed header that commits the application hash.
    pub const fn committing_header_hash(&self) -> &[u8; 32] {
        &self.committing_header_hash
    }

    /// Returns the authenticated primary RPC peer used for this update.
    pub const fn primary_peer_id(&self) -> tendermint::node::Id {
        self.primary_peer_id
    }

    /// Returns the distinct authenticated witness RPC peers.
    pub fn witness_peer_ids(&self) -> &[tendermint::node::Id] {
        &self.witness_peer_ids
    }
}

/// Successful finality verification plus the exact next durable trust root.
#[derive(Clone, Debug)]
pub struct VerifiedFinalityUpdate {
    receipt: CometBftFinalityReceipt,
    next_trust_root: PinnedTrustRoot,
}

impl VerifiedFinalityUpdate {
    /// Returns the finality capability for the requested execution output.
    pub const fn receipt(&self) -> &CometBftFinalityReceipt {
        &self.receipt
    }

    /// Returns the verified committing header to persist as the next trust root.
    pub const fn next_trust_root(&self) -> &PinnedTrustRoot {
        &self.next_trust_root
    }

    /// Splits the update into its finality receipt and next trusted state.
    pub fn into_parts(self) -> (CometBftFinalityReceipt, PinnedTrustRoot) {
        (self.receipt, self.next_trust_root)
    }
}

/// Verifies adjacent CometBFT headers and binds them to Thunderbolt execution.
#[derive(Clone, Debug)]
pub struct FinalityVerifier<A> {
    ledger_chain_id: LedgerChainIdV2,
    application_version: u64,
    policy: FinalityPolicy,
    verifier: ProdVerifier,
    source_authenticator: A,
}

impl<A: TraceSourceAuthenticator> FinalityVerifier<A> {
    /// Creates a v2 verifier for one Ledger chain, immutable policy, and a
    /// trusted primary/witness source authenticator.
    pub fn new(ledger_chain_id: LedgerChainIdV2, policy: FinalityPolicy, source_authenticator: A) -> Self {
        Self {
            ledger_chain_id,
            application_version: THUNDERBOLT_APP_VERSION_V2,
            policy,
            verifier: ProdVerifier::default(),
            source_authenticator,
        }
    }

    /// Returns the only accepted Ledger chain id.
    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    /// Returns the only accepted ABCI application version.
    pub const fn application_version(&self) -> u64 {
        self.application_version
    }

    /// Returns the immutable light-client policy.
    pub const fn policy(&self) -> FinalityPolicy {
        self.policy
    }

    /// Verifies a strictly adjacent primary trace and independent witness
    /// traces ending one height after `execution`.
    ///
    /// The trace begins at `trusted.height + 1` and must end at
    /// `execution.height + 1`. Requiring every adjacent header avoids silently
    /// substituting a partial bisection implementation. A runtime may advance
    /// and persist trust roots in smaller batches when the gap is large.
    pub fn verify_execution(
        &self,
        trusted: &PinnedTrustRoot,
        primary_trace: &[LightBlock],
        witness_traces: &[&[LightBlock]],
        execution: &ExecutedBlockV2,
    ) -> Result<VerifiedFinalityUpdate, FinalityError> {
        let verification_time = trusted_system_time()?;
        let update = self.verify_execution_at(trusted, primary_trace, witness_traces, execution, verification_time)?;
        let release_time = trusted_system_time()?;
        if release_time < verification_time {
            return Err(FinalityError::Clock);
        }
        ensure_trust_period_at_release(trusted, self.policy, release_time)?;
        Ok(update)
    }

    fn verify_execution_at(
        &self,
        trusted: &PinnedTrustRoot,
        primary_trace: &[LightBlock],
        witness_traces: &[&[LightBlock]],
        execution: &ExecutedBlockV2,
        now: Time,
    ) -> Result<VerifiedFinalityUpdate, FinalityError> {
        self.validate_trust_root(trusted)?;
        execution
            .validate_chain_id(&self.ledger_chain_id)
            .map_err(|_| FinalityError::ExecutionBinding("Ledger chain id differs"))?;
        if primary_trace.is_empty() || primary_trace.len() > self.policy.max_adjacent_headers {
            return Err(FinalityError::InvalidTrace(
                "trace length is outside the configured bound",
            ));
        }
        let committing_height = execution
            .height()
            .checked_add(1)
            .ok_or(FinalityError::ExecutionBinding("execution height cannot advance"))?;
        if trusted.height() > execution.height() {
            return Err(FinalityError::InvalidTrace(
                "trust root is ahead of the execution height",
            ));
        }
        let expected_trace_len = committing_height
            .checked_sub(trusted.height())
            .and_then(|distance| usize::try_from(distance).ok())
            .ok_or(FinalityError::InvalidTrace("trace distance does not fit this platform"))?;
        if primary_trace.len() != expected_trace_len {
            return Err(FinalityError::InvalidTrace(
                "trace must contain every adjacent header through the committing height",
            ));
        }

        validate_witness_input_shape(primary_trace, witness_traces, self.policy)?;
        validate_total_work(primary_trace, witness_traces, self.policy)?;
        let authenticated_primary =
            self.authenticate_trace(TraceRole::Primary, trusted, committing_height, primary_trace)?;
        let mut authenticated_witnesses = Vec::with_capacity(witness_traces.len());
        for (index, witness) in witness_traces.iter().enumerate() {
            let index = u8::try_from(index)
                .map_err(|_| FinalityError::WitnessVerification("witness index does not fit in u8"))?;
            authenticated_witnesses.push(self.authenticate_trace(
                TraceRole::Witness(index),
                trusted,
                committing_height,
                witness,
            )?);
        }
        let primary_hashes = self.verify_trace(trusted, primary_trace, now)?;
        self.verify_witnesses(
            trusted,
            &authenticated_primary,
            &primary_hashes,
            &authenticated_witnesses,
            now,
        )?;

        let execution_light_block = if trusted.height() == execution.height() {
            &trusted.block
        } else {
            let offset = execution
                .height()
                .checked_sub(trusted.height())
                .and_then(|distance| distance.checked_sub(1))
                .and_then(|index| usize::try_from(index).ok())
                .ok_or(FinalityError::InvalidTrace("execution header position is invalid"))?;
            primary_trace
                .get(offset)
                .ok_or(FinalityError::InvalidTrace("execution header is absent from the trace"))?
        };
        let committing_block = primary_trace
            .last()
            .ok_or(FinalityError::InvalidTrace("committing header is absent"))?;
        bind_execution_headers(execution, execution_light_block, committing_block)?;

        let execution_header_hash = sha256_header_hash(&execution_light_block.signed_header.header)?;
        let committing_header_hash = sha256_header_hash(&committing_block.signed_header.header)?;
        let receipt = CometBftFinalityReceipt {
            ledger_chain_id: self.ledger_chain_id.clone(),
            application_version: self.application_version,
            execution_height: execution.height(),
            execution_block_time_ms: execution.block_time_ms(),
            application_hash: execution.app_hash().clone(),
            execution_header_hash,
            committing_height,
            committing_header_hash,
            primary_peer_id: authenticated_primary.peer_id,
            witness_peer_ids: authenticated_witnesses.iter().map(|witness| witness.peer_id).collect(),
        };
        Ok(VerifiedFinalityUpdate {
            receipt,
            next_trust_root: PinnedTrustRoot::from_verified(
                committing_block.clone(),
                committing_header_hash,
                self.ledger_chain_id.clone(),
                self.application_version,
                self.policy,
            ),
        })
    }

    fn validate_trust_root(&self, trusted: &PinnedTrustRoot) -> Result<(), FinalityError> {
        if trusted.ledger_chain_id != self.ledger_chain_id
            || trusted.application_version != self.application_version
            || trusted.policy != self.policy
        {
            return Err(FinalityError::InvalidTrustRoot(
                "chain, application version, or policy differs from the verifier",
            ));
        }
        validate_light_block_shape(&trusted.block, &self.ledger_chain_id, self.policy.max_validators)?;
        if trusted.block.signed_header.header.version.app != self.application_version
            || sha256_header_hash(&trusted.block.signed_header.header)? != trusted.header_hash
        {
            return Err(FinalityError::InvalidTrustRoot(
                "trusted header no longer matches its bound metadata",
            ));
        }
        Ok(())
    }

    fn verify_trace(
        &self,
        trusted: &PinnedTrustRoot,
        trace: &[LightBlock],
        now: Time,
    ) -> Result<Vec<[u8; 32]>, FinalityError> {
        let options = self.policy.verifier_options();
        let mut previous = &trusted.block;
        let mut previous_hash = trusted.header_hash;
        let mut hashes = Vec::with_capacity(trace.len());
        for (index, candidate) in trace.iter().enumerate() {
            validate_light_block_shape(candidate, &self.ledger_chain_id, self.policy.max_validators)?;
            if candidate.signed_header.header.version.app != self.application_version {
                return Err(FinalityError::InvalidTrace("ABCI application version differs"));
            }
            let step = u64::try_from(index)
                .map_err(|_| FinalityError::InvalidTrace("trace index does not fit in u64"))?
                .checked_add(1)
                .ok_or(FinalityError::InvalidTrace("trace index overflow"))?;
            let expected_height = trusted
                .height()
                .checked_add(step)
                .ok_or(FinalityError::InvalidTrace("trace height overflow"))?;
            if height_u64(candidate)? != expected_height {
                return Err(FinalityError::InvalidTrace("trace heights are not strictly adjacent"));
            }
            let last_block_hash = candidate
                .signed_header
                .header
                .last_block_id
                .as_ref()
                .map(|block_id| block_id.hash.as_bytes());
            if last_block_hash != Some(previous_hash.as_slice()) {
                return Err(FinalityError::InvalidTrace(
                    "header does not extend the exact prior header hash",
                ));
            }
            let verdict = catch_unwind(AssertUnwindSafe(|| {
                self.verifier.verify_update_header(
                    candidate.as_untrusted_state(),
                    previous.as_trusted_state(),
                    &options,
                    now,
                )
            }))
            .map_err(|_| FinalityError::LightClientVerification)?;
            if !matches!(verdict, Verdict::Success) {
                return Err(FinalityError::LightClientVerification);
            }
            previous_hash = sha256_header_hash(&candidate.signed_header.header)?;
            hashes.push(previous_hash);
            previous = candidate;
        }
        Ok(hashes)
    }

    fn verify_witnesses(
        &self,
        trusted: &PinnedTrustRoot,
        primary_trace: &AuthenticatedTrace<'_>,
        primary_hashes: &[[u8; 32]],
        witness_traces: &[AuthenticatedTrace<'_>],
        now: Time,
    ) -> Result<(), FinalityError> {
        if witness_traces.len() < self.policy.min_witnesses || witness_traces.len() > self.policy.max_witnesses {
            return Err(FinalityError::WitnessVerification(
                "witness count is outside the configured bound",
            ));
        }
        if primary_trace.role != TraceRole::Primary {
            return Err(FinalityError::WitnessVerification(
                "primary trace authentication role differs",
            ));
        }
        let primary_provider = primary_trace.peer_id;
        let mut witness_providers = Vec::with_capacity(witness_traces.len());
        for witness in witness_traces {
            if !matches!(witness.role, TraceRole::Witness(_)) || witness.blocks.len() != primary_trace.blocks.len() {
                return Err(FinalityError::WitnessVerification("witness trace length differs"));
            }
            let provider = witness.peer_id;
            if provider == primary_provider || witness_providers.contains(&provider) {
                return Err(FinalityError::WitnessVerification(
                    "primary and witnesses must have distinct provider identities",
                ));
            }
            let hashes = self.verify_trace(trusted, witness.blocks, now)?;
            if hashes != primary_hashes {
                return Err(FinalityError::WitnessVerification("witness header chain conflicts"));
            }
            witness_providers.push(provider);
        }
        Ok(())
    }

    fn authenticate_trace<'a>(
        &self,
        role: TraceRole,
        trusted: &PinnedTrustRoot,
        committing_height: u64,
        blocks: &'a [LightBlock],
    ) -> Result<AuthenticatedTrace<'a>, FinalityError> {
        let first_height = trusted
            .height()
            .checked_add(1)
            .ok_or(FinalityError::InvalidTrace("first trace height overflows"))?;
        let request = TraceAuthenticationRequest {
            role,
            ledger_chain_id: self.ledger_chain_id.clone(),
            first_height,
            last_height: committing_height,
            blocks,
        };
        let capability = TraceAuthenticationCapability { role, blocks };
        self.source_authenticator
            .authenticate(request, capability)
            .map_err(|_| FinalityError::WitnessVerification("trace source authentication failed"))
    }
}

fn validate_light_block_shape(
    block: &LightBlock,
    expected_chain_id: &LedgerChainIdV2,
    max_validators: usize,
) -> Result<(), FinalityError> {
    if block.signed_header.header.chain_id.as_str() != expected_chain_id.as_str() {
        return Err(FinalityError::InvalidTrace("CometBFT chain id differs"));
    }
    if block.validators.validators.is_empty()
        || block.validators.validators.len() > max_validators
        || block.next_validators.validators.is_empty()
        || block.next_validators.validators.len() > max_validators
    {
        return Err(FinalityError::InvalidTrace(
            "validator set size is outside the configured bound",
        ));
    }
    if block.signed_header.commit.signatures.len() != block.validators.validators.len()
        || block.signed_header.commit.signatures.len() > max_validators
    {
        return Err(FinalityError::InvalidTrace(
            "commit signature count does not match the bounded validator set",
        ));
    }
    if block.signed_header.commit.height != block.signed_header.header.height {
        return Err(FinalityError::InvalidTrace(
            "commit height does not match the signed header",
        ));
    }
    if block.signed_header.header.app_hash.as_bytes().len() != 32 {
        return Err(FinalityError::InvalidTrace(
            "Thunderbolt CometBFT application hashes must be exactly 32 bytes",
        ));
    }
    let validator_name_bytes = block
        .validators
        .validators
        .iter()
        .chain(block.next_validators.validators.iter())
        .try_fold(0_usize, |total, validator| {
            total.checked_add(validator.name.as_deref().map_or(0, str::len))
        })
        .ok_or(FinalityError::InvalidTrace("validator-name byte count overflows"))?;
    if validator_name_bytes > MAX_VALIDATOR_NAME_BYTES {
        return Err(FinalityError::InvalidTrace(
            "validator metadata exceeds the decoded-byte budget",
        ));
    }
    validate_validator_set(&block.validators)?;
    validate_validator_set(&block.next_validators)?;
    if block
        .validators
        .validator(block.signed_header.header.proposer_address)
        .is_none()
    {
        return Err(FinalityError::InvalidTrace(
            "header proposer is absent from the current validator set",
        ));
    }
    if block.validators.hash() != block.signed_header.header.validators_hash
        || block.next_validators.hash() != block.signed_header.header.next_validators_hash
    {
        return Err(FinalityError::InvalidTrace(
            "validator-set hash does not match the header",
        ));
    }
    if block.signed_header.header.height.value() == 0 {
        return Err(FinalityError::InvalidTrace("height must be positive"));
    }
    Ok(())
}

fn bind_execution_headers(
    execution: &ExecutedBlockV2,
    execution_block: &LightBlock,
    committing_block: &LightBlock,
) -> Result<(), FinalityError> {
    if height_u64(execution_block)? != execution.height() {
        return Err(FinalityError::ExecutionBinding("execution header height differs"));
    }
    let expected_committing_height = execution
        .height()
        .checked_add(1)
        .ok_or(FinalityError::ExecutionBinding("execution height cannot advance"))?;
    if height_u64(committing_block)? != expected_committing_height {
        return Err(FinalityError::ExecutionBinding(
            "committing header is not the next height",
        ));
    }
    let execution_time_ms = unix_time_millis(execution_block.signed_header.header.time)?;
    if execution_time_ms != execution.block_time_ms() {
        return Err(FinalityError::ExecutionBinding("execution block time differs"));
    }
    if execution_block.signed_header.header.app_hash.as_bytes() != execution.previous_app_hash().as_bytes() {
        return Err(FinalityError::ExecutionBinding("previous application hash differs"));
    }
    if committing_block.signed_header.header.app_hash.as_bytes() != execution.app_hash().as_bytes() {
        return Err(FinalityError::ExecutionBinding("committing application hash differs"));
    }
    Ok(())
}

fn unix_time_millis(time: Time) -> Result<u64, FinalityError> {
    let nanos = time.unix_timestamp_nanos();
    if nanos <= 0 {
        return Err(FinalityError::ExecutionBinding(
            "CometBFT block time must be after Unix epoch",
        ));
    }
    u64::try_from(nanos / 1_000_000)
        .map_err(|_| FinalityError::ExecutionBinding("CometBFT block time does not fit in u64 milliseconds"))
}

fn height_u64(block: &LightBlock) -> Result<u64, FinalityError> {
    let height = block.signed_header.header.height.value();
    if height == 0 {
        Err(FinalityError::InvalidTrace("height must be positive"))
    } else {
        Ok(height)
    }
}

fn sha256_header_hash(header: &Header) -> Result<[u8; 32], FinalityError> {
    let hash = catch_unwind(AssertUnwindSafe(|| header.hash())).map_err(|_| FinalityError::HeaderHash)?;
    match hash {
        Hash::Sha256(bytes) => Ok(bytes),
        Hash::None => Err(FinalityError::HeaderHash),
    }
}

fn trusted_system_time() -> Result<Time, FinalityError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| FinalityError::Clock)?;
    let seconds = i64::try_from(duration.as_secs()).map_err(|_| FinalityError::Clock)?;
    Time::from_unix_timestamp(seconds, duration.subsec_nanos()).map_err(|_| FinalityError::Clock)
}

fn validate_total_work(
    primary_trace: &[LightBlock],
    witness_traces: &[&[LightBlock]],
    policy: FinalityPolicy,
) -> Result<(), FinalityError> {
    let signature_count = std::iter::once(primary_trace)
        .chain(witness_traces.iter().copied())
        .flat_map(|trace| trace.iter())
        .try_fold(0_usize, |total, block| {
            total.checked_add(block.signed_header.commit.signatures.len())
        })
        .ok_or(FinalityError::InvalidTrace("signature work count overflows"))?;
    let configured_budget = policy
        .max_validators
        .checked_mul(policy.max_adjacent_headers)
        .and_then(|count| count.checked_mul(policy.max_witnesses + 1))
        .ok_or(FinalityError::InvalidPolicy("signature work budget overflows"))?;
    if signature_count > configured_budget || signature_count > MAX_SIGNATURE_CHECKS_PER_CALL {
        return Err(FinalityError::InvalidTrace(
            "signature work exceeds the configured budget",
        ));
    }
    Ok(())
}

fn validate_witness_input_shape(
    primary_trace: &[LightBlock],
    witness_traces: &[&[LightBlock]],
    policy: FinalityPolicy,
) -> Result<(), FinalityError> {
    if witness_traces.len() < policy.min_witnesses || witness_traces.len() > policy.max_witnesses {
        return Err(FinalityError::WitnessVerification(
            "witness count is outside the configured bound",
        ));
    }
    if witness_traces.iter().any(|trace| {
        trace.len() != primary_trace.len() || trace.is_empty() || trace.len() > policy.max_adjacent_headers
    }) {
        return Err(FinalityError::WitnessVerification(
            "witness trace length is outside the configured bound",
        ));
    }
    Ok(())
}

fn validate_validator_set(validators: &tendermint::validator::Set) -> Result<(), FinalityError> {
    let mut addresses = BTreeSet::new();
    let mut total = 0_u64;
    for validator in validators.validators() {
        let power = validator.power();
        if tendermint::account::Id::from(validator.pub_key) != validator.address {
            return Err(FinalityError::InvalidTrace(
                "validator address is not derived from its public key",
            ));
        }
        if power == 0 || !addresses.insert(validator.address) {
            return Err(FinalityError::InvalidTrace(
                "validator set contains zero power or duplicate addresses",
            ));
        }
        total = total
            .checked_add(power)
            .ok_or(FinalityError::InvalidTrace("validator voting power overflows"))?;
    }
    if total != validators.total_voting_power().value() {
        return Err(FinalityError::InvalidTrace(
            "validator total voting power is inconsistent",
        ));
    }
    if validators
        .proposer()
        .as_ref()
        .is_some_and(|proposer| !addresses.contains(&proposer.address))
    {
        return Err(FinalityError::InvalidTrace("validator-set proposer is not a member"));
    }
    Ok(())
}

fn ensure_trust_period_at_release(
    trusted: &PinnedTrustRoot,
    policy: FinalityPolicy,
    release_time: Time,
) -> Result<(), FinalityError> {
    let expires_at =
        (trusted.block.signed_header.header.time + policy.trusting_period).map_err(|_| FinalityError::Clock)?;
    if expires_at <= release_time {
        return Err(FinalityError::LightClientVerification);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests;
