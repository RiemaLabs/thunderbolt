use std::fmt;
use std::time::{Duration, Instant};

use secp::Scalar;
use thunderbolt_core::paillier::{
    add_ciphertexts, decrypt_to_big_number, encrypt_plaintext, random_nonce_in_group, PaillierAccountLocal,
};
use thunderbolt_core::zkp::types::big_number_to_scalar;
use thunderbolt_core::zkp::{
    prove_invoice, prove_transfer, verify_anchor_transition, verify_invoice, verify_transfer, InvoiceStatement,
    InvoiceWitness, ProofContext, TransferStatement, TransferWitness,
};
use thunderbolt_core::{Result, ThunderboltError};

const BENCHMARK_WARMUP_ITERATIONS: usize = 3;

#[derive(Clone, Copy, Debug)]
pub struct SingleCommitteeBenchmarkConfig {
    pub iterations: usize,
}

impl Default for SingleCommitteeBenchmarkConfig {
    fn default() -> Self {
        Self { iterations: 100 }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct StageSummary {
    pub total: Duration,
    pub average: Duration,
    pub min: Duration,
    pub max: Duration,
}

#[derive(Clone, Debug)]
pub struct SingleCommitteeBenchmarkReport {
    pub iterations: usize,
    pub invoice_setup: StageSummary,
    pub invoice_prove: StageSummary,
    pub invoice_verify: StageSummary,
    pub transfer_setup: StageSummary,
    pub transfer_prove: StageSummary,
    pub anchor_verify: StageSummary,
    pub transfer_verify: StageSummary,
    pub bob_decrypt: StageSummary,
    pub committee_update: StageSummary,
    pub total_offchain_transfer: StageSummary,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SingleCommitteeIterationSample {
    pub invoice_setup: Duration,
    pub invoice_prove: Duration,
    pub invoice_verify: Duration,
    pub transfer_setup: Duration,
    pub transfer_prove: Duration,
    pub anchor_verify: Duration,
    pub transfer_verify: Duration,
    pub bob_decrypt: Duration,
    pub committee_update: Duration,
    pub total_offchain_transfer: Duration,
}

#[derive(Clone, Debug)]
struct StageAccumulator {
    total: Duration,
    min: Duration,
    max: Duration,
    count: usize,
}

impl Default for StageAccumulator {
    fn default() -> Self {
        Self {
            total: Duration::ZERO,
            min: Duration::ZERO,
            max: Duration::ZERO,
            count: 0,
        }
    }
}

impl StageAccumulator {
    fn record(&mut self, duration: Duration) {
        if self.count == 0 {
            self.min = duration;
            self.max = duration;
        } else {
            self.min = self.min.min(duration);
            self.max = self.max.max(duration);
        }
        self.total += duration;
        self.count += 1;
    }

    fn finish(&self) -> StageSummary {
        let average = if self.count == 0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(self.total.as_secs_f64() / self.count as f64)
        };

        StageSummary {
            total: self.total,
            average,
            min: self.min,
            max: self.max,
        }
    }
}

fn micros(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000_000.0
}

impl fmt::Display for SingleCommitteeBenchmarkReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "single-committee off-chain transfer benchmark")?;
        writeln!(f, "iterations: {}", self.iterations)?;
        writeln!(
            f,
            "scope: invoice -> proof1 -> proof2 -> bob decrypt -> committee update"
        )?;
        writeln!(f, "note: excludes Paillier key generation and any chain/network time")?;
        writeln!(
            f,
            "note: discards a fixed {}-iteration warmup before measurement",
            BENCHMARK_WARMUP_ITERATIONS
        )?;
        writeln!(f)?;
        writeln!(
            f,
            "stage                     avg (µs)   min (µs)   max (µs)   total (ms)"
        )?;
        writeln!(
            f,
            "---------------------------------------------------------------------"
        )?;
        for (label, summary) in [
            ("invoice_setup", &self.invoice_setup),
            ("invoice_prove", &self.invoice_prove),
            ("invoice_verify", &self.invoice_verify),
            ("transfer_setup", &self.transfer_setup),
            ("transfer_prove", &self.transfer_prove),
            ("anchor_verify", &self.anchor_verify),
            ("transfer_verify", &self.transfer_verify),
            ("bob_decrypt", &self.bob_decrypt),
            ("committee_update", &self.committee_update),
            ("total_offchain", &self.total_offchain_transfer),
        ] {
            writeln!(
                f,
                "{label:22} {:>10.2} {:>10.2} {:>10.2} {:>11.2}",
                micros(summary.average),
                micros(summary.min),
                micros(summary.max),
                summary.total.as_secs_f64() * 1_000.0,
            )?;
        }
        Ok(())
    }
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

fn benchmark_anchor_base() -> Scalar {
    scalar_from_u64(42).expect("fixed benchmark anchor base scalar must be valid")
}

pub(crate) fn aggregate_single_committee_report(
    iterations: usize,
    samples: &[SingleCommitteeIterationSample],
) -> SingleCommitteeBenchmarkReport {
    let mut invoice_setup = StageAccumulator::default();
    let mut invoice_prove = StageAccumulator::default();
    let mut invoice_verify = StageAccumulator::default();
    let mut transfer_setup = StageAccumulator::default();
    let mut transfer_prove = StageAccumulator::default();
    let mut anchor_verify = StageAccumulator::default();
    let mut transfer_verify = StageAccumulator::default();
    let mut bob_decrypt = StageAccumulator::default();
    let mut committee_update = StageAccumulator::default();
    let mut total_offchain_transfer = StageAccumulator::default();

    for sample in samples {
        invoice_setup.record(sample.invoice_setup);
        invoice_prove.record(sample.invoice_prove);
        invoice_verify.record(sample.invoice_verify);
        transfer_setup.record(sample.transfer_setup);
        transfer_prove.record(sample.transfer_prove);
        anchor_verify.record(sample.anchor_verify);
        transfer_verify.record(sample.transfer_verify);
        bob_decrypt.record(sample.bob_decrypt);
        committee_update.record(sample.committee_update);
        total_offchain_transfer.record(sample.total_offchain_transfer);
    }

    SingleCommitteeBenchmarkReport {
        iterations,
        invoice_setup: invoice_setup.finish(),
        invoice_prove: invoice_prove.finish(),
        invoice_verify: invoice_verify.finish(),
        transfer_setup: transfer_setup.finish(),
        transfer_prove: transfer_prove.finish(),
        anchor_verify: anchor_verify.finish(),
        transfer_verify: transfer_verify.finish(),
        bob_decrypt: bob_decrypt.finish(),
        committee_update: committee_update.finish(),
        total_offchain_transfer: total_offchain_transfer.finish(),
    }
}

fn run_single_committee_iteration(
    iteration: usize,
    bob_account: &PaillierAccountLocal,
    committee_account: &PaillierAccountLocal,
    anchor_base: secp::Point,
) -> Result<SingleCommitteeIterationSample> {
    let total_start = Instant::now();

    let holder_secret = scalar_from_u64(11 + iteration as u64)?;
    let refresh = scalar_from_u64(101 + (iteration as u64 % 97))?;
    let committee_share = scalar_from_u64(10_000 + iteration as u64)?;
    let joint_lock_before = add_scalars(holder_secret, committee_share)?.base_point_mul();

    let invoice_setup_start = Instant::now();
    let invoice_context = ProofContext::invoice(
        format!("ctx-{iteration}").into_bytes(),
        format!("invoice-{iteration}").into_bytes(),
    );
    let bob_nonce = random_nonce_in_group(bob_account.public_key());
    let committee_nonce = random_nonce_in_group(committee_account.public_key());
    let refresh_bn = thunderbolt_core::zkp::types::scalar_to_big_number(refresh);
    let delta = anchor_base * refresh;
    let bob_ciphertext = encrypt_plaintext(bob_account.public_key(), &refresh_bn, &bob_nonce)?;
    let committee_ciphertext = encrypt_plaintext(committee_account.public_key(), &refresh_bn, &committee_nonce)?;
    let invoice_statement = InvoiceStatement {
        context: invoice_context.clone(),
        anchor_base,
        bob_key: bob_account.public_key().clone(),
        committee_key: committee_account.public_key().clone(),
        delta,
        bob_ciphertext: bob_ciphertext.clone(),
        committee_ciphertext: committee_ciphertext.clone(),
    };
    let invoice_witness = InvoiceWitness {
        refresh,
        bob_nonce,
        committee_nonce,
    };
    let invoice_setup = invoice_setup_start.elapsed();

    let invoice_prove_start = Instant::now();
    let invoice_proof = prove_invoice(&invoice_statement, &invoice_witness)?;
    let invoice_prove = invoice_prove_start.elapsed();

    let invoice_verify_start = Instant::now();
    verify_invoice(&invoice_statement, &invoice_proof)?;
    let invoice_verify = invoice_verify_start.elapsed();

    let transfer_setup_start = Instant::now();
    let current_anchor = anchor_base * holder_secret;
    let holder_nonce = random_nonce_in_group(bob_account.public_key());
    let holder_bn = thunderbolt_core::zkp::types::scalar_to_big_number(holder_secret);
    let holder_component = encrypt_plaintext(bob_account.public_key(), &holder_bn, &holder_nonce)?;
    let next_holder_ciphertext = add_ciphertexts(bob_account.public_key(), &holder_component, &bob_ciphertext)?;
    let next_anchor = (current_anchor + delta).into_option().ok_or_else(|| {
        ThunderboltError::InvalidStateTransition("anchor transition unexpectedly hit infinity".to_string())
    })?;
    let transfer_statement = TransferStatement {
        context: ProofContext::transfer(
            format!("ctx-{iteration}").into_bytes(),
            (iteration + 1) as u64,
            format!("invoice-{iteration}").into_bytes(),
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
    let transfer_setup = transfer_setup_start.elapsed();

    let transfer_prove_start = Instant::now();
    let transfer_proof = prove_transfer(&transfer_statement, &transfer_witness)?;
    let transfer_prove = transfer_prove_start.elapsed();

    let anchor_verify_start = Instant::now();
    verify_anchor_transition(&current_anchor, &delta, &next_anchor)?;
    let anchor_verify = anchor_verify_start.elapsed();

    let transfer_verify_start = Instant::now();
    verify_transfer(&transfer_statement, &transfer_proof)?;
    let transfer_verify = transfer_verify_start.elapsed();

    let bob_decrypt_start = Instant::now();
    let next_holder_secret = big_number_to_scalar(&decrypt_to_big_number(
        bob_account.private_key(),
        &next_holder_ciphertext,
    )?)?;
    let bob_decrypt = bob_decrypt_start.elapsed();

    let committee_update_start = Instant::now();
    let refresh_from_committee = big_number_to_scalar(&decrypt_to_big_number(
        committee_account.private_key(),
        &committee_ciphertext,
    )?)?;
    let next_committee_share = sub_scalars(committee_share, refresh_from_committee)?;
    let joint_lock_after = add_scalars(next_holder_secret, next_committee_share)?.base_point_mul();
    if joint_lock_before != joint_lock_after {
        return Err(ThunderboltError::InvalidStateTransition(
            "joint on-chain lock key changed after off-chain refresh".to_string(),
        ));
    }
    let committee_update = committee_update_start.elapsed();

    Ok(SingleCommitteeIterationSample {
        invoice_setup,
        invoice_prove,
        invoice_verify,
        transfer_setup,
        transfer_prove,
        anchor_verify,
        transfer_verify,
        bob_decrypt,
        committee_update,
        total_offchain_transfer: total_start.elapsed(),
    })
}

pub(crate) fn collect_single_committee_samples(
    config: SingleCommitteeBenchmarkConfig,
) -> Result<Vec<SingleCommitteeIterationSample>> {
    if config.iterations == 0 {
        return Err(ThunderboltError::InvalidParameter(
            "benchmark iterations must be greater than zero".to_string(),
        ));
    }

    let bob_account = PaillierAccountLocal::new().ok_or_else(|| {
        ThunderboltError::CryptographicError("failed to initialize Bob's Paillier account".to_string())
    })?;
    let committee_account = PaillierAccountLocal::new().ok_or_else(|| {
        ThunderboltError::CryptographicError("failed to initialize committee Paillier account".to_string())
    })?;
    let anchor_base = benchmark_anchor_base().base_point_mul();

    let mut samples = Vec::with_capacity(config.iterations);
    for i in 0..(config.iterations + BENCHMARK_WARMUP_ITERATIONS) {
        let sample = run_single_committee_iteration(i, &bob_account, &committee_account, anchor_base)?;
        if i >= BENCHMARK_WARMUP_ITERATIONS {
            samples.push(sample);
        }
    }

    Ok(samples)
}

pub fn run_single_committee_benchmark(
    config: SingleCommitteeBenchmarkConfig,
) -> Result<SingleCommitteeBenchmarkReport> {
    let samples = collect_single_committee_samples(config)?;
    Ok(aggregate_single_committee_report(config.iterations, &samples))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_single_committee_report_tracks_totals() {
        let samples = vec![
            SingleCommitteeIterationSample {
                invoice_setup: Duration::from_millis(100),
                invoice_prove: Duration::from_millis(300),
                invoice_verify: Duration::from_millis(190),
                transfer_setup: Duration::from_millis(60),
                transfer_prove: Duration::from_millis(160),
                anchor_verify: Duration::from_micros(10),
                transfer_verify: Duration::from_millis(110),
                bob_decrypt: Duration::from_millis(30),
                committee_update: Duration::from_millis(30),
                total_offchain_transfer: Duration::from_millis(980),
            },
            SingleCommitteeIterationSample {
                invoice_setup: Duration::from_millis(110),
                invoice_prove: Duration::from_millis(310),
                invoice_verify: Duration::from_millis(195),
                transfer_setup: Duration::from_millis(65),
                transfer_prove: Duration::from_millis(155),
                anchor_verify: Duration::from_micros(12),
                transfer_verify: Duration::from_millis(108),
                bob_decrypt: Duration::from_millis(31),
                committee_update: Duration::from_millis(29),
                total_offchain_transfer: Duration::from_millis(1_003),
            },
        ];
        let report = aggregate_single_committee_report(samples.len(), &samples);

        assert!(report.total_offchain_transfer.total > Duration::ZERO);
        assert!(report.invoice_prove.total > Duration::ZERO);
        assert!(report.transfer_verify.total > Duration::ZERO);
        assert_eq!(report.iterations, 2);
        assert_eq!(report.total_offchain_transfer.min, Duration::from_millis(980));
        assert_eq!(report.total_offchain_transfer.max, Duration::from_millis(1_003));
    }
}
