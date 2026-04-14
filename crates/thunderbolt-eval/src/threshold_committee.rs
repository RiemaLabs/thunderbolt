use std::fmt;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use secp::Scalar;
use thunderbolt_core::paillier::{
    add_ciphertexts, decrypt_to_big_number, encrypt_plaintext, random_nonce_in_group, PaillierAccountLocal,
};
use thunderbolt_core::threshold::{
    create_threshold_refresh_distribution, verify_threshold_refresh_distribution, ThresholdCommittee,
};
use thunderbolt_core::zkp::types::big_number_to_scalar;
use thunderbolt_core::zkp::{
    prove_share_encryption, prove_transfer, verify_anchor_transition, verify_share_encryption, verify_transfer,
    ProofContext, ShareEncryptionStatement, ShareEncryptionWitness, TransferStatement, TransferWitness,
};
use thunderbolt_core::{Result, ThunderboltError};

#[derive(Clone, Debug)]
pub struct ThresholdCommitteeBenchmarkConfig {
    pub iterations: usize,
    pub committee_sizes: Vec<usize>,
}

impl Default for ThresholdCommitteeBenchmarkConfig {
    fn default() -> Self {
        Self {
            iterations: 5,
            committee_sizes: default_committee_sizes(),
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

#[derive(Clone, Copy, Debug)]
pub struct MaliciousSeries {
    pub label: &'static str,
    pub numerator: usize,
    pub denominator: usize,
}

#[derive(Clone, Debug)]
pub struct ThresholdStageBreakdown {
    pub vess_distribution: DurationSummary,
    pub distribution_verify: DurationSummary,
    pub transfer_prove_verify: DurationSummary,
    pub bob_decrypt: DurationSummary,
    pub committee_apply: DurationSummary,
    pub reconstruction: DurationSummary,
}

#[derive(Clone, Debug)]
pub struct ThresholdCommitteePoint {
    pub committee_size: usize,
    pub threshold: usize,
    pub malicious_label: &'static str,
    pub malicious_members: usize,
    pub honest_members: usize,
    pub total_latency: DurationSummary,
    pub committee_completion: DurationSummary,
    pub stage_breakdown: ThresholdStageBreakdown,
}

#[derive(Clone, Debug)]
pub struct ThresholdCommitteeBenchmarkReport {
    pub iterations: usize,
    pub committee_sizes: Vec<usize>,
    pub series: Vec<MaliciousSeries>,
    pub points: Vec<ThresholdCommitteePoint>,
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn fraction(series: MaliciousSeries) -> f64 {
    series.numerator as f64 / series.denominator as f64
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

fn default_committee_sizes() -> Vec<usize> {
    vec![6, 12, 18]
}

fn default_malicious_series() -> Vec<MaliciousSeries> {
    vec![
        MaliciousSeries {
            label: "0%",
            numerator: 0,
            denominator: 1,
        },
        MaliciousSeries {
            label: "16.7%",
            numerator: 1,
            denominator: 6,
        },
        MaliciousSeries {
            label: "33.3%",
            numerator: 1,
            denominator: 3,
        },
    ]
}

fn threshold_for_committee_size(committee_size: usize) -> usize {
    (2 * committee_size).div_ceil(3)
}

fn malicious_members_for_series(committee_size: usize, series: MaliciousSeries) -> usize {
    (committee_size * series.numerator) / series.denominator
}

#[derive(Clone, Debug)]
struct IterationStages {
    vess_distribution: Duration,
    distribution_verify: Duration,
    transfer_prove_verify: Duration,
    bob_decrypt: Duration,
    committee_apply: Duration,
    reconstruction: Duration,
    committee_completion: Duration,
    total: Duration,
}

fn committee_size_iteration(
    committee_size: usize,
    threshold: usize,
    malicious_members: usize,
    iteration: usize,
) -> Result<IterationStages> {
    let anchor_base = benchmark_anchor_base().base_point_mul();
    let refresh = scalar_from_u64(101 + (iteration as u64 % 97))?;
    let holder_secret = scalar_from_u64(11 + iteration as u64)?;
    let committee_secret = scalar_from_u64(10_000 + iteration as u64)?;
    let joint_lock_before = add_scalars(holder_secret, committee_secret)?.base_point_mul();

    let bob_account = PaillierAccountLocal::new().ok_or_else(|| {
        ThunderboltError::CryptographicError("failed to initialize Bob's Paillier account".to_string())
    })?;
    let mut committee = ThresholdCommittee::new(threshold, committee_size, anchor_base, committee_secret)?;

    let total_start = Instant::now();

    // Stage 1: VESS distribution (Bob creates encrypted shares + proofs)
    let vess_start = Instant::now();
    let invoice_context = ProofContext::invoice(
        format!("ctx-{committee_size}-{iteration}").into_bytes(),
        format!("invoice-{committee_size}-{iteration}").into_bytes(),
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
        threshold,
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
            format!("ctx-{committee_size}-{iteration}").into_bytes(),
            (iteration + 1) as u64,
            format!("invoice-{committee_size}-{iteration}").into_bytes(),
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
    let next_holder_secret = big_number_to_scalar(&decrypt_to_big_number(
        bob_account.private_key(),
        &next_holder_ciphertext,
    )?)?;
    let bob_decrypt = decrypt_start.elapsed();

    // Stage 5: Committee apply refresh shares
    let honest_members = committee_size.saturating_sub(malicious_members);
    if honest_members < threshold {
        return Err(ThunderboltError::ThresholdNotMet {
            required: threshold as u32,
            actual: honest_members as u32,
        });
    }

    let committee_apply_start = Instant::now();
    let honest_member_ids = committee
        .member_ids()
        .into_iter()
        .take(honest_members)
        .collect::<Vec<_>>();
    let mut per_member_durations = Vec::with_capacity(honest_members);
    for member_id in &honest_member_ids {
        let member_start = Instant::now();
        committee.apply_refresh_share(&refresh_distribution, *member_id)?;
        per_member_durations.push(member_start.elapsed());
    }
    per_member_durations.sort_unstable();
    let committee_completion = per_member_durations[threshold - 1];
    let committee_apply = committee_apply_start.elapsed();

    // Stage 6: Reconstruction
    let reconstruct_start = Instant::now();
    let reconstructed_committee_secret = committee.reconstruct_secret(&honest_member_ids[..threshold])?;
    let reconstruction = reconstruct_start.elapsed();

    let expected_committee_secret = sub_scalars(committee_secret, refresh)?;
    if reconstructed_committee_secret != expected_committee_secret {
        return Err(ThunderboltError::InvalidStateTransition(
            "threshold reconstruction did not match the expected committee secret after refresh".to_string(),
        ));
    }

    let joint_lock_after = add_scalars(next_holder_secret, reconstructed_committee_secret)?.base_point_mul();
    if joint_lock_before != joint_lock_after {
        return Err(ThunderboltError::InvalidStateTransition(
            "joint on-chain lock key changed after threshold committee refresh".to_string(),
        ));
    }

    let total = total_start.elapsed();

    Ok(IterationStages {
        vess_distribution,
        distribution_verify,
        transfer_prove_verify,
        bob_decrypt,
        committee_apply,
        reconstruction,
        committee_completion,
        total,
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

    let series = default_malicious_series();
    let mut points = Vec::new();
    let committee_sizes = if config.committee_sizes.is_empty() {
        default_committee_sizes()
    } else {
        config.committee_sizes.clone()
    };

    for committee_size in &committee_sizes {
        let threshold = threshold_for_committee_size(*committee_size);
        for malicious_series in &series {
            let malicious_members = malicious_members_for_series(*committee_size, *malicious_series);
            let mut committee_completion_samples = Vec::with_capacity(config.iterations);
            let mut total_latency_samples = Vec::with_capacity(config.iterations);
            let mut vess_dist_samples = Vec::with_capacity(config.iterations);
            let mut dist_verify_samples = Vec::with_capacity(config.iterations);
            let mut transfer_pv_samples = Vec::with_capacity(config.iterations);
            let mut bob_decrypt_samples = Vec::with_capacity(config.iterations);
            let mut committee_apply_samples = Vec::with_capacity(config.iterations);
            let mut reconstruction_samples = Vec::with_capacity(config.iterations);

            for iteration in 0..config.iterations {
                let stages =
                    committee_size_iteration(*committee_size, threshold, malicious_members, iteration)?;
                committee_completion_samples.push(stages.committee_completion);
                total_latency_samples.push(stages.total);
                vess_dist_samples.push(stages.vess_distribution);
                dist_verify_samples.push(stages.distribution_verify);
                transfer_pv_samples.push(stages.transfer_prove_verify);
                bob_decrypt_samples.push(stages.bob_decrypt);
                committee_apply_samples.push(stages.committee_apply);
                reconstruction_samples.push(stages.reconstruction);
            }

            points.push(ThresholdCommitteePoint {
                committee_size: *committee_size,
                threshold,
                malicious_label: malicious_series.label,
                malicious_members,
                honest_members: committee_size - malicious_members,
                total_latency: summarize(&total_latency_samples)?,
                committee_completion: summarize(&committee_completion_samples)?,
                stage_breakdown: ThresholdStageBreakdown {
                    vess_distribution: summarize(&vess_dist_samples)?,
                    distribution_verify: summarize(&dist_verify_samples)?,
                    transfer_prove_verify: summarize(&transfer_pv_samples)?,
                    bob_decrypt: summarize(&bob_decrypt_samples)?,
                    committee_apply: summarize(&committee_apply_samples)?,
                    reconstruction: summarize(&reconstruction_samples)?,
                },
            });
        }
    }

    Ok(ThresholdCommitteeBenchmarkReport {
        iterations: config.iterations,
        committee_sizes,
        series,
        points,
    })
}

impl ThresholdCommitteeBenchmarkReport {
    pub fn to_csv_string(&self) -> String {
        let mut csv = String::from(
            "committee_size,threshold,malicious_label,malicious_fraction,malicious_members,honest_members,total_latency_avg_ms,total_latency_p50_ms,total_latency_p95_ms,total_latency_p99_ms,total_latency_min_ms,total_latency_max_ms,committee_completion_avg_ms,committee_completion_p50_ms,committee_completion_p95_ms,committee_completion_p99_ms,committee_completion_min_ms,committee_completion_max_ms,iterations\n",
        );

        let mut points = self.points.iter().collect::<Vec<_>>();
        points.sort_by_key(|point| (point.committee_size, point.malicious_members));

        for point in points {
            let malicious_series = self
                .series
                .iter()
                .find(|series| series.label == point.malicious_label)
                .expect("benchmark point should always map back to its malicious-fraction series");
            csv.push_str(&format!(
                "{},{},{},{:.4},{},{},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{}\n",
                point.committee_size,
                point.threshold,
                point.malicious_label,
                fraction(*malicious_series),
                point.malicious_members,
                point.honest_members,
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
        writeln!(f, "threshold committee benchmark (real implementation)")?;
        writeln!(f, "iterations: {}", self.iterations)?;
        writeln!(f, "x-axis: committee members")?;
        writeln!(f, "lines: 0%, 16.7%, 33.3% malicious members")?;
        writeln!(f, "threshold policy: t = ceil(2n/3)")?;
        writeln!(f)?;
        writeln!(f, "total transfer latency avg / p95 (ms)")?;
        writeln!(
            f,
            "committee size   0% malicious         16.7% malicious      33.3% malicious"
        )?;
        writeln!(
            f,
            "----------------------------------------------------------------------------"
        )?;
        for committee_size in &self.committee_sizes {
            write!(f, "{committee_size:>14} ")?;
            for malicious_series in &self.series {
                let point = self
                    .points
                    .iter()
                    .find(|point| {
                        point.committee_size == *committee_size && point.malicious_label == malicious_series.label
                    })
                    .expect("all committee sizes and malicious series should have a benchmark point");
                write!(
                    f,
                    "{:>7.2}/{:>7.2} ",
                    millis(point.total_latency.average),
                    millis(point.total_latency.p95),
                )?;
            }
            writeln!(f)?;
        }

        writeln!(f)?;
        writeln!(f, "committee completion avg / p95 (ms)")?;
        writeln!(
            f,
            "committee size   0% malicious         16.7% malicious      33.3% malicious"
        )?;
        writeln!(
            f,
            "----------------------------------------------------------------------------"
        )?;
        for committee_size in &self.committee_sizes {
            write!(f, "{committee_size:>14} ")?;
            for malicious_series in &self.series {
                let point = self
                    .points
                    .iter()
                    .find(|point| {
                        point.committee_size == *committee_size && point.malicious_label == malicious_series.label
                    })
                    .expect("all committee sizes and malicious series should have a benchmark point");
                write!(
                    f,
                    "{:>7.2}/{:>7.2} ",
                    millis(point.committee_completion.average),
                    millis(point.committee_completion.p95),
                )?;
            }
            writeln!(f)?;
        }

        // Stage breakdown table (0% malicious only, for clarity)
        writeln!(f)?;
        writeln!(f, "stage breakdown avg (ms), 0% malicious")?;
        writeln!(
            f,
            "committee size   VESS dist   dist verify   xfer p+v   bob dec   cmte apply   reconstr"
        )?;
        writeln!(
            f,
            "------------------------------------------------------------------------------------"
        )?;
        for committee_size in &self.committee_sizes {
            let point = self
                .points
                .iter()
                .find(|point| point.committee_size == *committee_size && point.malicious_label == "0%")
                .expect("all committee sizes should have a 0% malicious benchmark point");
            let bd = &point.stage_breakdown;
            writeln!(
                f,
                "{:>14} {:>9.1} {:>13.1} {:>10.1} {:>9.1} {:>12.1} {:>10.1}",
                committee_size,
                millis(bd.vess_distribution.average),
                millis(bd.distribution_verify.average),
                millis(bd.transfer_prove_verify.average),
                millis(bd.bob_decrypt.average),
                millis(bd.committee_apply.average),
                millis(bd.reconstruction.average),
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_policy_is_two_thirds_rounded_up() {
        assert_eq!(threshold_for_committee_size(6), 4);
        assert_eq!(threshold_for_committee_size(12), 8);
        assert_eq!(threshold_for_committee_size(18), 12);
    }

    #[test]
    fn malicious_series_matches_requested_fractions() {
        let series = default_malicious_series();
        assert_eq!(malicious_members_for_series(6, series[0]), 0);
        assert_eq!(malicious_members_for_series(6, series[1]), 1);
        assert_eq!(malicious_members_for_series(6, series[2]), 2);
        assert_eq!(malicious_members_for_series(12, series[1]), 2);
        assert_eq!(malicious_members_for_series(12, series[2]), 4);
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
    fn csv_export_contains_all_series() {
        let report = ThresholdCommitteeBenchmarkReport {
            iterations: 1,
            committee_sizes: vec![6],
            series: default_malicious_series(),
            points: vec![ThresholdCommitteePoint {
                committee_size: 6,
                threshold: 4,
                malicious_label: "16.7%",
                malicious_members: 1,
                honest_members: 5,
                total_latency: dummy_summary(2700),
                committee_completion: dummy_summary(130),
                stage_breakdown: ThresholdStageBreakdown {
                    vess_distribution: dummy_summary(1500),
                    distribution_verify: dummy_summary(400),
                    transfer_prove_verify: dummy_summary(500),
                    bob_decrypt: dummy_summary(30),
                    committee_apply: dummy_summary(240),
                    reconstruction: dummy_summary(30),
                },
            }],
        };

        let csv = report.to_csv_string();
        assert!(csv.starts_with("committee_size,threshold"));
        assert!(csv.contains("16.7%,0.1667,1,5,2700.000"));
    }
}
