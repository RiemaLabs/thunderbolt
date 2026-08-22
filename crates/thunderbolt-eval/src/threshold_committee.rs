use std::fmt;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use secp::Scalar;
use thunderbolt_core::paillier::{add_ciphertexts, encrypt_plaintext, random_nonce_in_group, PaillierAccountLocal};
use thunderbolt_core::threshold::{
    create_threshold_refresh_distribution, verify_threshold_refresh_distribution, ThresholdCommittee,
};
use thunderbolt_core::zkp::types::big_number_to_scalar;
use thunderbolt_core::zkp::{
    prove_share_encryption, prove_transfer, verify_anchor_transition, verify_share_encryption, verify_transfer,
    ProofContext, ShareEncryptionStatement, ShareEncryptionWitness, TransferStatement, TransferWitness,
};
use thunderbolt_core::{Result, ThunderboltError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitteeShape {
    pub threshold: usize,
    pub committee_size: usize,
}

impl CommitteeShape {
    pub fn new(threshold: usize, committee_size: usize) -> Result<Self> {
        if threshold == 0 || committee_size < threshold {
            return Err(ThunderboltError::InvalidParameter(format!(
                "invalid committee shape: threshold={threshold}, committee_size={committee_size}"
            )));
        }
        Ok(Self {
            threshold,
            committee_size,
        })
    }

    pub fn label(&self) -> String {
        format!("{}-of-{}", self.threshold, self.committee_size)
    }

    pub fn slack_members(&self) -> usize {
        self.committee_size - self.threshold
    }
}

#[derive(Clone, Debug)]
pub struct ThresholdCommitteeBenchmarkConfig {
    pub iterations: usize,
    pub committee_shapes: Vec<CommitteeShape>,
    pub baseline_rtt: Duration,
    pub fanout: usize,
}

impl Default for ThresholdCommitteeBenchmarkConfig {
    fn default() -> Self {
        Self {
            iterations: 3,
            committee_shapes: default_committee_shapes(),
            baseline_rtt: Duration::from_millis(160),
            fanout: 4,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DurationSummary {
    pub average: Duration,
    pub p50: Duration,
    pub p95: Duration,
    pub p99: Duration,
    pub min: Duration,
    pub max: Duration,
}

#[derive(Clone, Debug)]
pub struct ThresholdCommitteePoint {
    pub committee_shape: CommitteeShape,
    pub delayed_members: usize,
    pub delayed_fraction: f64,
    pub total_latency: DurationSummary,
    pub committee_completion: DurationSummary,
}

#[derive(Clone, Debug)]
pub struct ThresholdCommitteeBenchmarkReport {
    pub iterations: usize,
    pub committee_shapes: Vec<CommitteeShape>,
    pub baseline_rtt: Duration,
    pub fanout: usize,
    pub points: Vec<ThresholdCommitteePoint>,
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn scalar_from_u64(value: u64) -> Result<Scalar> {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes());
    Scalar::from_slice(&bytes).map_err(|_| {
        ThunderboltError::OutOfRange(format!("value {value} does not fit into a non-zero secp256k1 scalar"))
    })
}

fn add_scalars(left: Scalar, right: Scalar) -> Result<Scalar> {
    (left + right).not_zero().map_err(|_| {
        ThunderboltError::InvalidStateTransition("scalar addition unexpectedly wrapped to zero".to_string())
    })
}

fn sub_scalars(left: Scalar, right: Scalar) -> Result<Scalar> {
    (left - right).not_zero().map_err(|_| {
        ThunderboltError::InvalidStateTransition("scalar subtraction unexpectedly wrapped to zero".to_string())
    })
}

fn percentile(sorted: &[Duration], numerator: usize, denominator: usize) -> Duration {
    let index = ((sorted.len() - 1) * numerator).div_ceil(denominator);
    sorted[index]
}

fn summarize(samples: &[Duration]) -> Result<DurationSummary> {
    if samples.is_empty() {
        return Err(ThunderboltError::InvalidParameter(
            "cannot summarize an empty duration sample set".to_string(),
        ));
    }

    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let total = samples.iter().fold(Duration::ZERO, |acc, duration| acc + *duration);
    let average = Duration::from_secs_f64(total.as_secs_f64() / samples.len() as f64);

    Ok(DurationSummary {
        average,
        p50: percentile(&sorted, 50, 100),
        p95: percentile(&sorted, 95, 100),
        p99: percentile(&sorted, 99, 100),
        min: *sorted.first().unwrap(),
        max: *sorted.last().unwrap(),
    })
}

fn benchmark_anchor_base() -> Scalar {
    scalar_from_u64(42).expect("fixed benchmark anchor base scalar must be valid")
}

fn default_committee_shapes() -> Vec<CommitteeShape> {
    vec![
        CommitteeShape::new(67, 100).expect("67-of-100 must be valid"),
        CommitteeShape::new(34, 50).expect("34-of-50 must be valid"),
        CommitteeShape::new(11, 15).expect("11-of-15 must be valid"),
        CommitteeShape::new(3, 5).expect("3-of-5 must be valid"),
    ]
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = value;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

/// Returns a multiplicative jitter factor in [0.8, 1.2] (±20% variance)
/// using a deterministic PRNG seeded by committee shape, iteration, and member id.
fn member_jitter_factor(committee_shape: CommitteeShape, iteration: usize, member_id: u32) -> f64 {
    let seed = ((committee_shape.threshold as u64) << 48)
        ^ ((committee_shape.committee_size as u64) << 32)
        ^ ((iteration as u64) << 8)
        ^ u64::from(member_id);
    let raw = splitmix64(seed) as f64 / u64::MAX as f64;
    0.8 + 0.4 * raw
}

#[derive(Clone, Copy, Debug)]
struct MemberResponse {
    member_id: u32,
    base_completion: Duration,
}

#[derive(Debug)]
struct IterationPrepared {
    committee: ThresholdCommittee,
    expected_committee_secret: Scalar,
    joint_lock_before: secp::Point,
    next_holder_secret: Scalar,
    fixed_prefix: Duration,
    base_responses: Vec<MemberResponse>,
}

#[derive(Clone, Debug)]
struct IterationStages {
    committee_completion: Duration,
    total: Duration,
}

fn prepare_committee_shape_iteration(
    committee_shape: CommitteeShape,
    iteration: usize,
    config: &ThresholdCommitteeBenchmarkConfig,
) -> Result<IterationPrepared> {
    let anchor_base = benchmark_anchor_base().base_point_mul();
    let refresh = scalar_from_u64(101 + (iteration as u64 % 97))?;
    let holder_secret = scalar_from_u64(11 + iteration as u64)?;
    let committee_secret = scalar_from_u64(10_000 + iteration as u64)?;
    let joint_lock_before = add_scalars(holder_secret, committee_secret)?.base_point_mul();

    let bob_account = PaillierAccountLocal::new().ok_or_else(|| {
        ThunderboltError::CryptographicError("failed to initialize Bob's Paillier account".to_string())
    })?;
    let mut committee = ThresholdCommittee::new(
        committee_shape.threshold,
        committee_shape.committee_size,
        anchor_base,
        committee_secret,
    )?;

    // Stage 1: VESS distribution (Bob creates encrypted shares + proofs)
    let vess_start = Instant::now();
    let invoice_context = ProofContext::invoice(
        format!("ctx-{}-{iteration}", committee_shape.label()).into_bytes(),
        format!("invoice-{}-{iteration}", committee_shape.label()).into_bytes(),
    );
    let bob_nonce = random_nonce_in_group(bob_account.public_key());
    let refresh_bn = thunderbolt_core::zkp::types::scalar_to_big_number(refresh);
    let bob_ciphertext = encrypt_plaintext(bob_account.public_key(), &refresh_bn, &bob_nonce)?;
    let bob_statement = ShareEncryptionStatement {
        context: invoice_context.clone(),
        anchor_base,
        recipient_key: bob_account.public_key().clone(),
        member_id: 0,
        committed_point: anchor_base * refresh,
        ciphertext: bob_ciphertext.clone(),
    };
    let bob_proof = prove_share_encryption(
        &bob_statement,
        &ShareEncryptionWitness {
            secret: refresh,
            nonce: bob_nonce,
        },
    )?;
    let refresh_distribution = create_threshold_refresh_distribution(
        invoice_context.clone(),
        anchor_base,
        committee_shape.threshold,
        refresh,
        &committee.member_public_keys(),
    )?;
    let vess_distribution = vess_start.elapsed();

    // Stage 2: Distribution verification
    let verify_start = Instant::now();
    verify_share_encryption(&bob_statement, &bob_proof)?;
    verify_threshold_refresh_distribution(&refresh_distribution)?;
    let distribution_verify = verify_start.elapsed();

    // Stage 3: Transfer prove + verify
    let transfer_start = Instant::now();
    let current_anchor = anchor_base * holder_secret;
    let holder_nonce = random_nonce_in_group(bob_account.public_key());
    let holder_bn = thunderbolt_core::zkp::types::scalar_to_big_number(holder_secret);
    let holder_component = encrypt_plaintext(bob_account.public_key(), &holder_bn, &holder_nonce)?;
    let next_holder_ciphertext = add_ciphertexts(bob_account.public_key(), &holder_component, &bob_ciphertext)?;
    let next_anchor = (current_anchor + refresh_distribution.delta)
        .into_option()
        .ok_or_else(|| {
            ThunderboltError::InvalidStateTransition("anchor transition unexpectedly hit infinity".to_string())
        })?;
    let transfer_statement = TransferStatement {
        context: ProofContext::transfer(
            format!("ctx-{}-{iteration}", committee_shape.label()).into_bytes(),
            (iteration + 1) as u64,
            format!("invoice-{}-{iteration}", committee_shape.label()).into_bytes(),
        ),
        anchor_base,
        bob_key: bob_account.public_key().clone(),
        current_anchor,
        invoice_ciphertext: bob_ciphertext.clone(),
        next_holder_ciphertext: next_holder_ciphertext.clone(),
    };
    let transfer_witness = TransferWitness {
        holder_secret,
        holder_nonce,
    };
    let transfer_proof = prove_transfer(&transfer_statement, &transfer_witness)?;
    verify_anchor_transition(&current_anchor, &refresh_distribution.delta, &next_anchor)?;
    verify_transfer(&transfer_statement, &transfer_proof)?;
    let transfer_prove_verify = transfer_start.elapsed();

    // Stage 4: Bob decrypt
    let decrypt_start = Instant::now();
    let next_holder_secret = big_number_to_scalar(&bob_account.decrypt_big_number(&next_holder_ciphertext)?)?;
    let bob_decrypt = decrypt_start.elapsed();

    // Stage 5: apply all refresh shares once; delay behavior is injected later in the benchmark harness.
    // Model fanout: Bob sends shares in waves of `fanout` members, each wave taking one RTT.
    // Each honest member's response has ±20% multiplicative variance for realism.
    let mut base_responses = Vec::with_capacity(committee_shape.committee_size);
    for member_id in committee.member_ids() {
        let member_start = Instant::now();
        committee.apply_refresh_share(&refresh_distribution, member_id)?;
        let local_apply = member_start.elapsed();
        let batch_index = member_id as usize / config.fanout;
        let batch_delay = config.baseline_rtt * batch_index as u32;
        let deterministic_base = config.baseline_rtt + batch_delay + local_apply;
        let jitter_factor = member_jitter_factor(committee_shape, iteration, member_id);
        let base_completion = Duration::from_secs_f64(deterministic_base.as_secs_f64() * jitter_factor);
        base_responses.push(MemberResponse {
            member_id,
            base_completion,
        });
    }
    base_responses.sort_by_key(|response| response.base_completion);

    Ok(IterationPrepared {
        committee,
        expected_committee_secret: sub_scalars(committee_secret, refresh)?,
        joint_lock_before,
        next_holder_secret,
        fixed_prefix: vess_distribution + distribution_verify + transfer_prove_verify + bob_decrypt,
        base_responses,
    })
}

fn stages_from_prepared_iteration(
    prepared: &IterationPrepared,
    committee_shape: CommitteeShape,
    delayed_members: usize,
) -> Result<IterationStages> {
    let n = committee_shape.committee_size;
    let non_responsive_ids: Vec<u32> = if delayed_members == 0 {
        Vec::new()
    } else {
        (0..delayed_members)
            .map(|i| ((i * n) / delayed_members) as u32)
            .collect()
    };

    let mut responses: Vec<MemberResponse> = prepared
        .base_responses
        .iter()
        .filter(|r| !non_responsive_ids.contains(&r.member_id))
        .cloned()
        .collect();
    responses.sort_by_key(|response| response.base_completion);

    if responses.len() < committee_shape.threshold {
        return Err(ThunderboltError::ThresholdNotMet {
            required: committee_shape.threshold as u32,
            actual: responses.len() as u32,
        });
    }

    let committee_completion = responses[committee_shape.threshold - 1].base_completion;

    let reconstruct_start = Instant::now();
    let reconstructed_committee_secret = prepared.committee.reconstruct_secret(
        &responses
            .iter()
            .take(committee_shape.threshold)
            .map(|response| response.member_id)
            .collect::<Vec<_>>(),
    )?;
    let reconstruction = reconstruct_start.elapsed();

    if reconstructed_committee_secret != prepared.expected_committee_secret {
        return Err(ThunderboltError::InvalidStateTransition(
            "threshold reconstruction did not match the expected committee secret after refresh".to_string(),
        ));
    }

    let joint_lock_after = add_scalars(prepared.next_holder_secret, reconstructed_committee_secret)?.base_point_mul();
    if prepared.joint_lock_before != joint_lock_after {
        return Err(ThunderboltError::InvalidStateTransition(
            "joint on-chain lock key changed after threshold committee refresh".to_string(),
        ));
    }

    Ok(IterationStages {
        committee_completion,
        total: prepared.fixed_prefix + committee_completion + reconstruction,
    })
}

pub fn run_threshold_committee_suite(
    config: ThresholdCommitteeBenchmarkConfig,
) -> Result<ThresholdCommitteeBenchmarkReport> {
    if config.iterations == 0 {
        return Err(ThunderboltError::InvalidParameter(
            "threshold committee benchmark iterations must be greater than zero".to_string(),
        ));
    }

    let committee_shapes = if config.committee_shapes.is_empty() {
        default_committee_shapes()
    } else {
        config.committee_shapes.clone()
    };

    #[derive(Default)]
    struct PointSamples {
        committee_completion: Vec<Duration>,
        total_latency: Vec<Duration>,
    }

    let mut points = Vec::new();
    for committee_shape in &committee_shapes {
        let mut point_samples = (0..=committee_shape.slack_members())
            .map(|_| PointSamples {
                committee_completion: Vec::with_capacity(config.iterations),
                total_latency: Vec::with_capacity(config.iterations),
            })
            .collect::<Vec<_>>();

        for iteration in 0..config.iterations {
            let prepared = prepare_committee_shape_iteration(*committee_shape, iteration, &config)?;
            for (delayed_members, samples) in point_samples.iter_mut().enumerate() {
                let stages = stages_from_prepared_iteration(&prepared, *committee_shape, delayed_members)?;
                samples.committee_completion.push(stages.committee_completion);
                samples.total_latency.push(stages.total);
            }
        }

        for (delayed_members, samples) in point_samples.into_iter().enumerate() {
            let delayed_fraction = if committee_shape.slack_members() == 0 {
                0.0
            } else {
                delayed_members as f64 / committee_shape.slack_members() as f64
            };
            points.push(ThresholdCommitteePoint {
                committee_shape: *committee_shape,
                delayed_members,
                delayed_fraction,
                total_latency: summarize(&samples.total_latency)?,
                committee_completion: summarize(&samples.committee_completion)?,
            });
        }
    }

    Ok(ThresholdCommitteeBenchmarkReport {
        iterations: config.iterations,
        committee_shapes,
        baseline_rtt: config.baseline_rtt,
        fanout: config.fanout,
        points,
    })
}

impl ThresholdCommitteeBenchmarkReport {
    pub fn to_csv_string(&self) -> String {
        let mut csv = String::from(
            "committee_label,committee_size,threshold,slack_members,non_responsive_members,non_responsive_fraction,baseline_rtt_ms,fanout,total_latency_avg_ms,total_latency_p50_ms,total_latency_p95_ms,total_latency_p99_ms,total_latency_min_ms,total_latency_max_ms,committee_completion_avg_ms,committee_completion_p50_ms,committee_completion_p95_ms,committee_completion_p99_ms,committee_completion_min_ms,committee_completion_max_ms,iterations\n",
        );

        for point in &self.points {
            csv.push_str(&format!(
                "{},{},{},{},{},{:.4},{:.3},{},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{}\n",
                point.committee_shape.label(),
                point.committee_shape.committee_size,
                point.committee_shape.threshold,
                point.committee_shape.slack_members(),
                point.delayed_members,
                point.delayed_fraction,
                millis(self.baseline_rtt),
                self.fanout,
                millis(point.total_latency.average),
                millis(point.total_latency.p50),
                millis(point.total_latency.p95),
                millis(point.total_latency.p99),
                millis(point.total_latency.min),
                millis(point.total_latency.max),
                millis(point.committee_completion.average),
                millis(point.committee_completion.p50),
                millis(point.committee_completion.p95),
                millis(point.committee_completion.p99),
                millis(point.committee_completion.min),
                millis(point.committee_completion.max),
                self.iterations,
            ));
        }

        csv
    }

    pub fn write_csv<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                ThunderboltError::StorageError(format!(
                    "failed to create benchmark artifact directory {}: {err}",
                    parent.display()
                ))
            })?;
        }

        fs::write(path, self.to_csv_string()).map_err(|err| {
            ThunderboltError::StorageError(format!(
                "failed to write threshold benchmark CSV {}: {err}",
                path.display()
            ))
        })
    }
}

impl fmt::Display for ThresholdCommitteeBenchmarkReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "threshold committee delay benchmark (real implementation)")?;
        writeln!(f, "iterations: {}", self.iterations)?;
        writeln!(f, "x-axis: delayed fraction f / (n - t)")?;
        writeln!(
            f,
            "committee setups: {}",
            self.committee_shapes
                .iter()
                .map(CommitteeShape::label)
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        writeln!(f, "baseline RTT (ms): {:.1}", millis(self.baseline_rtt))?;
        writeln!(f, "fanout: {}", self.fanout)?;
        writeln!(f, "response jitter: +/-20%")?;
        writeln!(f)?;
        writeln!(
            f,
            "shape             f/(n-t)   delayed   total avg/p95 (ms)   committee avg/p95 (ms)"
        )?;
        writeln!(
            f,
            "--------------------------------------------------------------------------------"
        )?;
        for point in &self.points {
            writeln!(
                f,
                "{:>10} {:>11.3} {:>9} {:>9.2}/{:>7.2} {:>12.2}/{:>7.2}",
                point.committee_shape.label(),
                point.delayed_fraction,
                point.delayed_members,
                millis(point.total_latency.average),
                millis(point.total_latency.p95),
                millis(point.committee_completion.average),
                millis(point.committee_completion.p95),
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committee_shape_validates_bounds() {
        assert!(CommitteeShape::new(3, 5).is_ok());
        assert!(CommitteeShape::new(0, 5).is_err());
        assert!(CommitteeShape::new(6, 5).is_err());
    }

    #[test]
    fn default_committee_shapes_follow_requested_roast_setups() {
        let shapes = default_committee_shapes();
        let labels = shapes.iter().map(CommitteeShape::label).collect::<Vec<_>>();
        assert_eq!(labels, vec!["67-of-100", "34-of-50", "11-of-15", "3-of-5"]);
    }

    fn dummy_summary(ms: u64) -> DurationSummary {
        DurationSummary {
            average: Duration::from_millis(ms),
            p50: Duration::from_millis(ms),
            p95: Duration::from_millis(ms),
            p99: Duration::from_millis(ms),
            min: Duration::from_millis(ms),
            max: Duration::from_millis(ms),
        }
    }

    #[test]
    fn csv_export_contains_shape_and_delayed_fraction() {
        let report = ThresholdCommitteeBenchmarkReport {
            iterations: 1,
            committee_shapes: vec![CommitteeShape::new(3, 5).unwrap()],
            baseline_rtt: Duration::from_millis(160),
            fanout: 4,
            points: vec![ThresholdCommitteePoint {
                committee_shape: CommitteeShape::new(3, 5).unwrap(),
                delayed_members: 1,
                delayed_fraction: 0.5,
                total_latency: dummy_summary(800),
                committee_completion: dummy_summary(320),
            }],
        };

        let csv = report.to_csv_string();
        assert!(csv.starts_with("committee_label,committee_size,threshold"));
        assert!(csv.contains("3-of-5,5,3,2,1,0.5000,160.000,4,800.000"));
    }
}
