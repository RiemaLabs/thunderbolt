use std::fmt;
use std::time::{Duration, Instant};

use secp::Scalar;
use thunderbolt_core::paillier::{
    add_ciphertexts, decrypt_to_big_number, encrypt_plaintext, random_nonce_in_group, PaillierAccountLocal,
};
use thunderbolt_core::zkp::types::{big_number_to_scalar, scalar_to_big_number};
use thunderbolt_core::zkp::{
    prove_invoice, prove_transfer, verify_anchor_transition, verify_invoice, verify_transfer, InvoiceStatement,
    InvoiceWitness, ProofContext, TransferStatement, TransferWitness,
};
use thunderbolt_core::{Result, ThunderboltError};

#[derive(Clone, Debug)]
pub struct ScalabilityBenchmarkConfig {
    pub chain_lengths: Vec<usize>,
}

impl Default for ScalabilityBenchmarkConfig {
    fn default() -> Self {
        Self {
            chain_lengths: vec![1, 10, 50, 100, 500, 1000],
        }
    }
}

#[derive(Clone, Debug)]
pub struct ScalabilityPoint {
    pub chain_length: usize,
    pub per_transfer_avg_ms: f64,
    pub per_transfer_min_ms: f64,
    pub per_transfer_max_ms: f64,
    pub per_transfer_p50_ms: f64,
    pub per_transfer_p95_ms: f64,
    pub total_chain_ms: f64,
    pub cumulative_proof_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct ScalabilityBenchmarkReport {
    pub points: Vec<ScalabilityPoint>,
}

const PROOF_SIZE_INVOICE_BYTES: usize = 2_355;
const PROOF_SIZE_TRANSFER_BYTES: usize = 1_540;
const PROOF_SIZE_PER_TRANSFER: usize = PROOF_SIZE_INVOICE_BYTES + PROOF_SIZE_TRANSFER_BYTES;

fn scalar_from_u64(value: u64) -> Result<Scalar> {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes());
    Scalar::from_slice(&bytes).map_err(|_| {
        ThunderboltError::OutOfRange(format!("value {value} does not fit into a non-zero secp256k1 scalar"))
    })
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn percentile_duration(sorted: &[Duration], pct: usize) -> Duration {
    let index = ((sorted.len() - 1) * pct) / 100;
    sorted[index]
}

fn run_transfer_chain(chain_length: usize) -> Result<(Vec<Duration>, Duration)> {
    let bob_account = PaillierAccountLocal::new().ok_or_else(|| {
        ThunderboltError::CryptographicError("failed to initialize Bob's Paillier account".to_string())
    })?;
    let committee_account = PaillierAccountLocal::new().ok_or_else(|| {
        ThunderboltError::CryptographicError("failed to initialize committee Paillier account".to_string())
    })?;

    let anchor_base = scalar_from_u64(42)?.base_point_mul();
    let mut holder_secret = scalar_from_u64(11)?;
    let mut committee_share = scalar_from_u64(10_000)?;

    let mut per_transfer_durations = Vec::with_capacity(chain_length);
    let chain_start = Instant::now();

    for step in 0..chain_length {
        let transfer_start = Instant::now();

        let refresh = scalar_from_u64(101 + (step as u64 % 97))?;

        // Invoice phase
        let invoice_context = ProofContext::invoice(
            format!("scalability-ctx-{step}").into_bytes(),
            format!("scalability-invoice-{step}").into_bytes(),
        );
        let bob_nonce = random_nonce_in_group(bob_account.public_key());
        let committee_nonce = random_nonce_in_group(committee_account.public_key());
        let refresh_bn = scalar_to_big_number(refresh);
        let delta = anchor_base * refresh;
        let bob_ciphertext = encrypt_plaintext(bob_account.public_key(), &refresh_bn, &bob_nonce)?;
        let committee_ciphertext = encrypt_plaintext(committee_account.public_key(), &refresh_bn, &committee_nonce)?;
        let invoice_statement = InvoiceStatement {
            context: invoice_context,
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
        let invoice_proof = prove_invoice(&invoice_statement, &invoice_witness)?;
        verify_invoice(&invoice_statement, &invoice_proof)?;

        // Transfer phase
        let current_anchor = anchor_base * holder_secret;
        let holder_nonce = random_nonce_in_group(bob_account.public_key());
        let holder_bn = scalar_to_big_number(holder_secret);
        let holder_component = encrypt_plaintext(bob_account.public_key(), &holder_bn, &holder_nonce)?;
        let next_holder_ciphertext = add_ciphertexts(bob_account.public_key(), &holder_component, &bob_ciphertext)?;
        let next_anchor = (current_anchor + delta).into_option().ok_or_else(|| {
            ThunderboltError::InvalidStateTransition("anchor transition hit infinity".to_string())
        })?;
        let transfer_statement = TransferStatement {
            context: ProofContext::transfer(
                format!("scalability-ctx-{step}").into_bytes(),
                (step + 1) as u64,
                format!("scalability-invoice-{step}").into_bytes(),
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
        verify_anchor_transition(&current_anchor, &delta, &next_anchor)?;
        verify_transfer(&transfer_statement, &transfer_proof)?;

        // State update
        let next_holder_secret = big_number_to_scalar(&decrypt_to_big_number(
            bob_account.private_key(),
            &next_holder_ciphertext,
        )?)?;
        let refresh_from_committee = big_number_to_scalar(&decrypt_to_big_number(
            committee_account.private_key(),
            &committee_ciphertext,
        )?)?;
        let next_committee_share = (committee_share - refresh_from_committee).not_zero().map_err(|_| {
            ThunderboltError::InvalidStateTransition("committee share wrapped to zero".to_string())
        })?;

        holder_secret = next_holder_secret;
        committee_share = next_committee_share;

        per_transfer_durations.push(transfer_start.elapsed());
    }

    let total_chain = chain_start.elapsed();
    Ok((per_transfer_durations, total_chain))
}

pub fn run_scalability_benchmark(config: ScalabilityBenchmarkConfig) -> Result<ScalabilityBenchmarkReport> {
    let mut points = Vec::with_capacity(config.chain_lengths.len());

    for chain_length in &config.chain_lengths {
        let (durations, total_chain) = run_transfer_chain(*chain_length)?;

        let total_ms: f64 = durations.iter().map(|d| millis(*d)).sum();
        let avg_ms = total_ms / durations.len() as f64;
        let min_ms = durations.iter().map(|d| millis(*d)).fold(f64::INFINITY, f64::min);
        let max_ms = durations.iter().map(|d| millis(*d)).fold(0.0, f64::max);

        let mut sorted = durations.clone();
        sorted.sort_unstable();
        let p50_ms = millis(percentile_duration(&sorted, 50));
        let p95_ms = millis(percentile_duration(&sorted, 95));

        points.push(ScalabilityPoint {
            chain_length: *chain_length,
            per_transfer_avg_ms: avg_ms,
            per_transfer_min_ms: min_ms,
            per_transfer_max_ms: max_ms,
            per_transfer_p50_ms: p50_ms,
            per_transfer_p95_ms: p95_ms,
            total_chain_ms: millis(total_chain),
            cumulative_proof_bytes: chain_length * PROOF_SIZE_PER_TRANSFER,
        });
    }

    Ok(ScalabilityBenchmarkReport { points })
}

impl ScalabilityBenchmarkReport {
    pub fn to_csv_string(&self) -> String {
        let mut csv = String::from(
            "chain_length,per_transfer_avg_ms,per_transfer_min_ms,per_transfer_max_ms,per_transfer_p50_ms,per_transfer_p95_ms,total_chain_ms,cumulative_proof_kb\n",
        );
        for point in &self.points {
            csv.push_str(&format!(
                "{},{:.2},{:.2},{:.2},{:.2},{:.2},{:.1},{:.1}\n",
                point.chain_length,
                point.per_transfer_avg_ms,
                point.per_transfer_min_ms,
                point.per_transfer_max_ms,
                point.per_transfer_p50_ms,
                point.per_transfer_p95_ms,
                point.total_chain_ms,
                point.cumulative_proof_bytes as f64 / 1024.0,
            ));
        }
        csv
    }
}

impl fmt::Display for ScalabilityBenchmarkReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "scalability benchmark: sequential transfer chain")?;
        writeln!(f, "measures per-transfer latency as chain depth grows")?;
        writeln!(f)?;
        writeln!(
            f,
            "chain len   avg (ms)   p50 (ms)   p95 (ms)   min (ms)   max (ms)   total (s)   proof (KB)"
        )?;
        writeln!(
            f,
            "--------------------------------------------------------------------------------------------"
        )?;
        for point in &self.points {
            writeln!(
                f,
                "{:>9} {:>10.2} {:>10.2} {:>10.2} {:>10.2} {:>10.2} {:>11.2} {:>11.1}",
                point.chain_length,
                point.per_transfer_avg_ms,
                point.per_transfer_p50_ms,
                point.per_transfer_p95_ms,
                point.per_transfer_min_ms,
                point.per_transfer_max_ms,
                point.total_chain_ms / 1_000.0,
                point.cumulative_proof_bytes as f64 / 1024.0,
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_chain_completes_successfully() {
        let report = run_scalability_benchmark(ScalabilityBenchmarkConfig {
            chain_lengths: vec![1, 3],
        })
        .expect("scalability benchmark should complete");

        assert_eq!(report.points.len(), 2);
        assert!(report.points[0].per_transfer_avg_ms > 0.0);
        assert!(report.points[1].per_transfer_avg_ms > 0.0);
        assert_eq!(report.points[0].cumulative_proof_bytes, PROOF_SIZE_PER_TRANSFER);
        assert_eq!(report.points[1].cumulative_proof_bytes, 3 * PROOF_SIZE_PER_TRANSFER);
    }
}
