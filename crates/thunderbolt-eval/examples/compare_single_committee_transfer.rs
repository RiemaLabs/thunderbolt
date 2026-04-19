use std::path::PathBuf;
use std::process::Command;

fn preferred_protoc() -> Option<String> {
    std::env::var("PROTOC")
        .ok()
        .filter(|candidate| PathBuf::from(candidate).exists())
        .or_else(|| {
            let helper = PathBuf::from("benchmarks/ensure_protoc.sh");
            if !helper.exists() {
                return None;
            }
            let output = Command::new("bash").arg(&helper).output().ok()?;
            if !output.status.success() {
                return None;
            }
            let candidate = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if candidate.is_empty() {
                None
            } else {
                Some(candidate)
            }
        })
        .or_else(|| {
        std::env::var_os("PATH").and_then(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join("protoc"))
                .find(|candidate| candidate.exists())
                .map(|candidate| candidate.display().to_string())
        })
    })
}

use thunderbolt_mock::benchmark::{run_single_committee_benchmark, SingleCommitteeBenchmarkConfig};
use thunderbolt_mock::comparison::{
    format_groth16_comparison, format_lightning_comparison, format_local_lightning_comparison,
    format_sp1_comparison, Groth16BenchmarkReport, LocalLightningBenchmarkReport, Sp1BenchmarkReport,
};

fn main() {
    let mut iterations = 10usize;
    let mut with_sp1 = false;
    let mut sp1_paillier_bits = 256usize;
    let mut with_groth16 = false;
    let mut with_local_lightning = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--with-sp1" {
            with_sp1 = true;
        } else if arg == "--sp1-paillier-bits" {
            sp1_paillier_bits = args
                .next()
                .expect("--sp1-paillier-bits requires a value")
                .parse::<usize>()
                .expect("invalid --sp1-paillier-bits value");
        } else if arg == "--with-groth16" {
            with_groth16 = true;
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
            let mut command = Command::new("cargo");
            command.args([
                "run",
                "--release",
                "--",
                "--prove",
                "--iterations",
                &iterations.to_string(),
                "--paillier-bits",
                &sp1_paillier_bits.to_string(),
                "--json",
            ]);
            if let Some(protoc) = preferred_protoc() {
                command.env("PROTOC", protoc);
            }
            let output = command
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
                    "  (cd {} && PROTOC={} cargo run --release -- --prove --iterations {} --paillier-bits {} --json)",
                    sp1_script_dir.display(),
                    protoc,
                    iterations,
                    sp1_paillier_bits,
                );
            } else {
                println!(
                    "  (cd {} && cargo run --release -- --prove --iterations {} --paillier-bits {} --json)",
                    sp1_script_dir.display(),
                    iterations,
                    sp1_paillier_bits
                );
            }
            println!("or run this example with `--with-sp1` to execute the SP1 comparison automatically.");
        }
    }

    let groth16_script_dir = PathBuf::from("benchmarks/groth16-transfer-benchmark/script");
    if groth16_script_dir.exists() {
        if with_groth16 {
            let output = Command::new("cargo")
                .args(["run", "--release", "--", "--iterations", &iterations.to_string(), "--json"])
                .current_dir(&groth16_script_dir)
                .output()
                .expect("failed to launch Groth16 benchmark");
            if !output.status.success() {
                eprintln!(
                    "Groth16 benchmark failed:
{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                std::process::exit(1);
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            let json_start = stdout.find('{').expect("Groth16 benchmark did not emit JSON");
            let groth16: Groth16BenchmarkReport =
                serde_json::from_str(&stdout[json_start..]).expect("failed to parse Groth16 JSON");
            println!("{}", format_groth16_comparison(&report, &groth16));
        } else {
            println!("groth16 comparison command:");
            println!(
                "  (cd {} && cargo run --release -- --iterations {} --json)",
                groth16_script_dir.display(),
                iterations
            );
            println!("or run this example with `--with-groth16` to execute the Groth16 comparison automatically.");
        }
    }
}
