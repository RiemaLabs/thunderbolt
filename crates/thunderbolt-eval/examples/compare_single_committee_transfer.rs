use std::path::PathBuf;
use std::process::Command;

fn preferred_protoc() -> Option<String> {
    std::env::var("PROTOC").ok().or_else(|| {
        let fallback = PathBuf::from("/tmp/protoc29/bin/protoc");
        fallback.exists().then(|| fallback.display().to_string())
    })
}

use thunderbolt_mock::benchmark::{run_single_committee_benchmark, SingleCommitteeBenchmarkConfig};
use thunderbolt_mock::comparison::{
    format_lightning_comparison, format_local_lightning_comparison, format_sp1_comparison,
    LocalLightningBenchmarkReport, Sp1BenchmarkReport,
};

fn main() {
    let mut iterations = 10usize;
    let mut with_sp1 = false;
    let mut with_local_lightning = false;

    for arg in std::env::args().skip(1) {
        if arg == "--with-sp1" {
            with_sp1 = true;
        } else if arg == "--with-local-lightning" {
            with_local_lightning = true;
        } else if let Ok(value) = arg.parse::<usize>() {
            iterations = value;
        }
    }

    let report = run_single_committee_benchmark(SingleCommitteeBenchmarkConfig { iterations })
        .expect("single-committee benchmark should complete successfully");

    println!("{report}");
    println!("{}", format_lightning_comparison(&report));

    if with_local_lightning {
        let output = Command::new("python3")
            .args([
                "benchmarks/local-lightning-benchmark/run_benchmark.py",
                "--iterations",
                &iterations.to_string(),
                "--json",
            ])
            .current_dir(".")
            .output()
            .expect("failed to launch local Lightning benchmark");
        if !output.status.success() {
            eprintln!(
                "local Lightning benchmark failed:
{}",
                String::from_utf8_lossy(&output.stderr)
            );
            std::process::exit(1);
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let json_start = stdout.find('{').expect("local Lightning benchmark did not emit JSON");
        let local_ln: LocalLightningBenchmarkReport =
            serde_json::from_str(&stdout[json_start..]).expect("failed to parse local Lightning JSON");
        println!("{}", format_local_lightning_comparison(&report, &local_ln));
    }

    let sp1_script_dir = PathBuf::from("benchmarks/sp1-transfer-benchmark/script");
    if sp1_script_dir.exists() {
        if with_sp1 {
            let output = Command::new("cargo")
                .args([
                    "run",
                    "--release",
                    "--",
                    "--prove",
                    "--iterations",
                    &iterations.to_string(),
                    "--json",
                ])
                .env("PROTOC", "/tmp/protoc29/bin/protoc")
                .env("RUSTUP_TOOLCHAIN", "1.91.1-aarch64-apple-darwin")
                .current_dir(&sp1_script_dir)
                .output()
                .expect("failed to launch SP1 benchmark");
            if !output.status.success() {
                eprintln!(
                    "SP1 benchmark failed:
{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                std::process::exit(1);
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            let json_start = stdout.find('{').expect("SP1 benchmark did not emit JSON");
            let sp1: Sp1BenchmarkReport =
                serde_json::from_str(&stdout[json_start..]).expect("failed to parse SP1 JSON");
            println!("{}", format_sp1_comparison(&report, &sp1));
        } else {
            println!("sp1 comparison command:");
            if let Some(protoc) = preferred_protoc() {
                println!(
                    "  (cd {} && PROTOC={} cargo run --release -- --prove --iterations {} --json)",
                    sp1_script_dir.display(),
                    protoc,
                    iterations
                );
            } else {
                println!(
                    "  (cd {} && cargo run --release -- --prove --iterations {} --json)",
                    sp1_script_dir.display(),
                    iterations
                );
            }
            println!("or run this example with `--with-sp1` to execute the SP1 comparison automatically.");
        }
    }
}
