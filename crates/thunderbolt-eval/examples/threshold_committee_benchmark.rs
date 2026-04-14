use std::path::PathBuf;

use thunderbolt_mock::threshold_committee::{run_threshold_committee_suite, ThresholdCommitteeBenchmarkConfig};

fn main() {
    let mut iterations = 5usize;
    let mut committee_sizes = Vec::new();
    let mut csv_path = PathBuf::from("artifacts/threshold-committee-benchmark.csv");
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--sizes" {
            let value = args.next().expect("--sizes requires a comma-separated value");
            committee_sizes = value
                .split(',')
                .filter_map(|item| item.trim().parse::<usize>().ok())
                .collect();
        } else if arg == "--csv" {
            csv_path = PathBuf::from(args.next().expect("--csv requires a file path"));
        } else if let Ok(value) = arg.parse::<usize>() {
            iterations = value;
        }
    }

    let report = run_threshold_committee_suite(ThresholdCommitteeBenchmarkConfig {
        iterations,
        committee_sizes,
    })
    .expect("threshold committee benchmark should complete successfully");

    println!("{report}");
    report
        .write_csv(&csv_path)
        .expect("threshold committee benchmark should write CSV successfully");
    println!("csv written to {}", csv_path.display());
}
