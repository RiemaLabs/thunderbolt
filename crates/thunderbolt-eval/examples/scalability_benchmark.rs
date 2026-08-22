use std::fs;
use std::path::PathBuf;

use thunderbolt_mock::scalability::{run_scalability_benchmark, ScalabilityBenchmarkConfig};

fn main() {
    let mut chain_lengths = Vec::new();
    let mut csv_path = PathBuf::from("artifacts/scalability-benchmark.csv");
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--lengths" {
            let value = args.next().expect("--lengths requires a comma-separated value");
            chain_lengths = value
                .split(',')
                .filter_map(|item| item.trim().parse::<usize>().ok())
                .collect();
        } else if arg == "--csv" {
            csv_path = PathBuf::from(args.next().expect("--csv requires a file path"));
        }
    }

    let config = if chain_lengths.is_empty() {
        ScalabilityBenchmarkConfig::default()
    } else {
        ScalabilityBenchmarkConfig { chain_lengths }
    };

    println!("running scalability benchmark...");
    for length in &config.chain_lengths {
        println!("  chain length {length}...");
    }

    let report = run_scalability_benchmark(config).expect("scalability benchmark should complete successfully");

    println!("{report}");

    if let Some(parent) = csv_path.parent() {
        fs::create_dir_all(parent).expect("failed to create artifact directory");
    }
    fs::write(&csv_path, report.to_csv_string()).expect("failed to write CSV");
    println!("csv written to {}", csv_path.display());
}
