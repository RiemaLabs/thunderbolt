use std::fmt;
use std::time::Duration;

use crate::benchmark::SingleCommitteeBenchmarkReport;

#[derive(Clone, Copy, Debug)]
pub struct LightningReference {
    pub name: &'static str,
    pub source: &'static str,
    pub latency: Duration,
    pub notes: &'static str,
}

#[derive(Clone, Copy, Debug)]
pub struct LightningComparison {
    pub reference: LightningReference,
    pub ours: Duration,
    pub speedup: f64,
}

fn secs(duration: Duration) -> f64 {
    duration.as_secs_f64()
}

pub fn default_lightning_references() -> &'static [LightningReference] {
    const REFERENCES: &[LightningReference] = &[
        LightningReference {
            name: "c-lightning probe RTT example",
            source: "Blockstream c-lightning probe plugin results",
            latency: Duration::from_micros(2_560_000),
            notes: "Example round-trip through 4 nodes / 3 channels.",
        },
        LightningReference {
            name: "c-lightning median completion",
            source: "Blockstream c-lightning probe plugin results",
            latency: Duration::from_micros(13_120_000),
            notes: "Median completion time with one attempt in probe experiment.",
        },
    ];
    REFERENCES
}

pub fn compare_to_lightning(report: &SingleCommitteeBenchmarkReport) -> Vec<LightningComparison> {
    let ours = report.total_offchain_transfer.average;
    default_lightning_references()
        .iter()
        .map(|reference| LightningComparison {
            reference: *reference,
            ours,
            speedup: secs(reference.latency) / secs(ours),
        })
        .collect()
}

pub fn format_lightning_comparison(report: &SingleCommitteeBenchmarkReport) -> String {
    let mut out = String::new();
    out.push_str("\nlightning reference comparison\n");
    out.push_str("our baseline is the measured single-committee off-chain transfer average\n");
    out.push_str("reference                             speedup   ours (s)   ref (s)\n");
    out.push_str("------------------------------------------------------------------\n");

    for item in compare_to_lightning(report) {
        let _ = fmt::write(
            &mut out,
            format_args!(
                "{:<36} {:>7.2}x {:>10.3} {:>9.3}\n",
                item.reference.name,
                item.speedup,
                secs(item.ours),
                secs(item.reference.latency),
            ),
        );
    }

    out.push_str("\nnotes:\n");
    for reference in default_lightning_references() {
        let _ = fmt::write(
            &mut out,
            format_args!("- {} ({}) — {}\n", reference.name, reference.source, reference.notes),
        );
    }

    out
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct Sp1StageSummary {
    pub total_secs: f64,
    pub average_secs: f64,
    pub min_secs: f64,
    pub max_secs: f64,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct Sp1BenchmarkReport {
    pub iterations: usize,
    pub paillier_bits: usize,
    pub execute: Option<Sp1StageSummary>,
    pub prove: Option<Sp1StageSummary>,
    pub verify: Option<Sp1StageSummary>,
    pub total: Sp1StageSummary,
}

pub fn format_sp1_comparison(report: &SingleCommitteeBenchmarkReport, sp1: &Sp1BenchmarkReport) -> String {
    let ours = secs(report.total_offchain_transfer.average);
    let mut out = String::new();
    out.push_str(
        "
sp1 comparison
",
    );
    out.push_str(
        "metric                               ours (s)   sp1 (s)   speedup
",
    );
    out.push_str(
        "----------------------------------------------------------------
",
    );
    let total_speedup = sp1.total.average_secs / ours;
    let _ = fmt::write(
        &mut out,
        format_args!(
            "{:<35} {:>8.3} {:>9.3} {:>8.2}x
",
            "total transfer benchmark", ours, sp1.total.average_secs, total_speedup,
        ),
    );
    if let Some(prove) = &sp1.prove {
        let specialized_prove = secs(report.invoice_prove.average + report.transfer_prove.average);
        let prove_speedup = prove.average_secs / specialized_prove;
        let _ = fmt::write(
            &mut out,
            format_args!(
                "{:<35} {:>8.3} {:>9.3} {:>8.2}x
",
                "zk prove path", specialized_prove, prove.average_secs, prove_speedup,
            ),
        );
    }
    if let Some(verify) = &sp1.verify {
        let specialized_verify = secs(report.invoice_verify.average + report.transfer_verify.average);
        let verify_speedup = verify.average_secs / specialized_verify;
        let _ = fmt::write(
            &mut out,
            format_args!(
                "{:<35} {:>8.3} {:>9.3} {:>8.2}x
",
                "zk verify path", specialized_verify, verify.average_secs, verify_speedup,
            ),
        );
    }
    let _ = fmt::write(
        &mut out,
        format_args!(
            "
sp1 paillier bits: {}
",
            sp1.paillier_bits
        ),
    );
    out
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct Groth16StageSummary {
    pub total_secs: f64,
    pub average_secs: f64,
    pub min_secs: f64,
    pub max_secs: f64,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct Groth16BenchmarkReport {
    pub iterations: usize,
    pub padding_muls: usize,
    pub constraints: usize,
    pub setup_secs: f64,
    pub prove: Groth16StageSummary,
    pub verify: Groth16StageSummary,
    pub total: Groth16StageSummary,
}

pub fn format_groth16_comparison(report: &SingleCommitteeBenchmarkReport, groth16: &Groth16BenchmarkReport) -> String {
    let ours = secs(report.total_offchain_transfer.average);
    let specialized_prove = secs(report.invoice_prove.average + report.transfer_prove.average);
    let specialized_verify = secs(report.invoice_verify.average + report.transfer_verify.average);
    let mut out = String::new();
    out.push_str(
        "
groth16 comparison
",
    );
    out.push_str(
        "metric                               ours (s)   groth16 (s)   speedup
",
    );
    out.push_str(
        "--------------------------------------------------------------------
",
    );
    let total_speedup = groth16.total.average_secs / ours;
    let _ = fmt::write(
        &mut out,
        format_args!(
            "{:<35} {:>8.3} {:>13.3} {:>8.2}x
",
            "total transfer benchmark", ours, groth16.total.average_secs, total_speedup,
        ),
    );
    let prove_speedup = groth16.prove.average_secs / specialized_prove;
    let _ = fmt::write(
        &mut out,
        format_args!(
            "{:<35} {:>8.3} {:>13.3} {:>8.2}x
",
            "zk prove path", specialized_prove, groth16.prove.average_secs, prove_speedup,
        ),
    );
    let verify_speedup = groth16.verify.average_secs / specialized_verify;
    let _ = fmt::write(
        &mut out,
        format_args!(
            "{:<35} {:>8.3} {:>13.3} {:>8.2}x
",
            "zk verify path", specialized_verify, groth16.verify.average_secs, verify_speedup,
        ),
    );
    let _ = fmt::write(
        &mut out,
        format_args!(
            "
constraints: {}
padding mul constraints: {}
trusted setup (excluded from per-transfer total): {:.3}s
",
            groth16.constraints, groth16.padding_muls, groth16.setup_secs
        ),
    );
    out
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct LocalLightningStageSummary {
    pub total_secs: f64,
    pub average_secs: f64,
    pub min_secs: f64,
    pub max_secs: f64,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct LocalLightningBenchmarkReport {
    pub iterations: usize,
    pub bootstrap_secs: f64,
    pub invoice_create: LocalLightningStageSummary,
    pub payment_settle: LocalLightningStageSummary,
    pub total_payment: LocalLightningStageSummary,
}

pub fn format_local_lightning_comparison(
    report: &SingleCommitteeBenchmarkReport,
    lightning: &LocalLightningBenchmarkReport,
) -> String {
    let ours = secs(report.total_offchain_transfer.average);
    let local_ln = lightning.total_payment.average_secs;
    let payment_speedup = local_ln / ours;
    let mut out = String::new();
    out.push_str(
        "
local lightning regtest comparison
",
    );
    out.push_str(
        "metric                               ours (s)   ln-local (s)   ratio
",
    );
    out.push_str(
        "--------------------------------------------------------------------
",
    );
    let _ = fmt::write(
        &mut out,
        format_args!(
            "{:<35} {:>8.3} {:>13.3} {:>8.2}x
",
            "total transfer benchmark", ours, local_ln, payment_speedup,
        ),
    );
    let _ = fmt::write(
        &mut out,
        format_args!(
            "{:<35} {:>8.3} {:>13.3} {:>8.2}x
",
            "invoice creation",
            secs(report.invoice_setup.average + report.invoice_prove.average),
            lightning.invoice_create.average_secs,
            lightning.invoice_create.average_secs / secs(report.invoice_setup.average + report.invoice_prove.average),
        ),
    );
    let _ = fmt::write(
        &mut out,
        format_args!(
            "{:<35} {:>8.3} {:>13.3} {:>8.2}x
",
            "payment / transfer completion",
            secs(report.transfer_setup.average + report.transfer_prove.average + report.transfer_verify.average),
            lightning.payment_settle.average_secs,
            lightning.payment_settle.average_secs
                / secs(report.transfer_setup.average + report.transfer_prove.average + report.transfer_verify.average),
        ),
    );
    let _ = fmt::write(
        &mut out,
        format_args!(
            "
bootstrap not included in LN per-payment comparison: {:.3}s
",
            lightning.bootstrap_secs
        ),
    );
    out
}
